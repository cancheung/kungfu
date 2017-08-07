package gateway

import (
	"errors"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/miekg/dns"
	"github.com/op/go-logging"
	"github.com/songgao/water"
	"github.com/yinheli/kungfu"
	"github.com/yinheli/kungfu/internal"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tun_name = "tun-kungfu-01"
	mtu      = 1500
)

var (
	log = kungfu.GetLog()

	realIpQueryLock sync.Mutex
)

type Gateway struct {
	RedisClient *redis.Client

	network        string
	proxy          *url.URL
	dialer         proxy.Dialer
	relayIp        net.IP
	relayPort      uint16
	nat            *nat
	ifce           *water.Interface
	relayTCPServer *net.TCPListener
	relayUDPServer *net.UDPConn
	udpTunnelLock  sync.Mutex
	udpTunnels     map[string]*net.UDPConn
}

func (g *Gateway) Serve() {

	err := g.loadConfig()
	if err != nil {
		return
	}

	g.nat = newNat()
	g.udpTunnels = make(map[string]*net.UDPConn)

	g.tunUp()
	go g.relayTCPServe()
	go g.relayUDPServe()
	go g.handleRequest()

	g.subscribe()
}

func (g *Gateway) loadConfig() (err error) {
	network, err := g.RedisClient.Get(internal.GetRedisNetworkKey()).Result()
	if err != nil {
		log.Error("get network config error, %v", err)
		return
	}

	_, _, err = internal.ParseNetwork(network)
	if err != nil {
		log.Error("parse network error %v", err)
		return
	}

	proxyStr, err := g.RedisClient.Get(internal.GetRedisProxyKey()).Result()
	if err != nil {
		log.Error("get proxy config error, %v", err)
		return
	}

	g.proxy, err = url.Parse(proxyStr)
	if err != nil {
		log.Error("parse proxy config error, %v", err)
		return
	}

	g.dialer, err = proxy.FromURL(g.proxy, proxy.Direct)
	if err != nil {
		log.Error("get proxy dialer error, %v", err)
		return
	}

	relayPortStr, err := g.RedisClient.Get(internal.GetRedisRelayPortKey()).Result()
	if err != nil {
		log.Error("get relay-port config error, %v", err)
		return
	}

	relayPort, err := strconv.ParseInt(relayPortStr, 10, 16)
	if err != nil {
		log.Error("invalid relay-port, %s %v", relayPortStr, err)
		return
	}

	relayIp, _, _ := net.ParseCIDR(network)

	g.network = network
	g.relayIp = relayIp
	g.relayPort = uint16(relayPort)

	log.Debug("network: %s, relayIp: %s, relayPort: %d",
		network, relayIp.String(), relayPort)

	return
}

func (g *Gateway) tunUp() {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = tun_name

	ifce, err := water.New(config)
	if err != nil {
		log.Error("create tun fail %v", err)
		os.Exit(1)
	}

	g.ifce = ifce

	g.configTun()
}

func (g *Gateway) relayTCPServe() {

	addr := &net.TCPAddr{IP: g.relayIp, Port: int(g.relayPort)}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		log.Error("start tcp relay server on port %d fail, %v", g.relayPort, err)
		return
	}

	log.Info("relay server listen on %d", g.relayPort)

	g.relayTCPServer = ln

	for {
		if g.relayTCPServer == nil {
			break
		}

		conn, err := g.relayTCPServer.AcceptTCP()
		if err != nil {
			log.Error("relay server accept request error, %v", err)
			time.Sleep(time.Second * 3)
			continue
		}

		go g.handleTCPRelayConn(conn)
	}
}

func (g *Gateway) relayUDPServe() {
	addr := &net.UDPAddr{IP: g.relayIp, Port: int(g.relayPort)}
	ln, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Error("start udp relay server on port %d fail, %v", g.relayPort, err)
		return
	}

	log.Info("relay server listen on %d", g.relayPort)

	g.relayUDPServer = ln

	for {
		if g.relayUDPServer == nil {
			break
		}

		buf := make([]byte, mtu)

		n, clientAddr, err := g.relayUDPServer.ReadFromUDP(buf)
		if err != nil {
			log.Error("relay udp server receive data error, %v", err)
			time.Sleep(time.Second * 3)
			continue
		}

		go g.handleUDPRelay(clientAddr, buf[:n])
	}
}

func (g *Gateway) configTun() {
	execCommand("ip", fmt.Sprintf("addr flush dev %s", g.ifce.Name()))

	err := execCommand("ip", fmt.Sprintf("addr add %s dev %s", g.network, g.ifce.Name()))
	if err != nil {
		log.Warning("set up tun addr error %v", err)
	}

	err = execCommand("ip", fmt.Sprintf("link set dev %s up mtu %d qlen 1000", g.ifce.Name(), mtu))
	if err != nil {
		log.Warning("up tun error %v", err)
	}
}

func (g *Gateway) handleRequest() {
	buffer := make([]byte, mtu)
	for {
		n, err := g.ifce.Read(buffer)
		if err != nil {
			log.Error("read tun ifce data error", err)
			break
		}

		packet := buffer[:n]

		if !isIPv4Packet(&packet) {
			continue
		}

		p := ipv4Packet(packet)

		protocol := p.protocol()
		if protocol == tcp {
			g.handleTCP(&p)
		} else if protocol == icmp {
			g.handleICMP(&p)
		} else if protocol == udp {
			g.handleUDP(&p)
		}
	}
}

func (g *Gateway) handleTCP(p *ipv4Packet) {
	tp := tcpPacket(p.payload())

	srcIp := p.sourceIP()
	dstIp := p.destinationIP()

	srcPort := tp.sourcePort()
	dstPort := tp.destinationPort()

	if srcPort == g.relayPort && g.relayIp.Equal(srcIp) {
		session := g.nat.getSession(dstPort)
		if session == nil {
			log.Warning("nat session not found, %v:%d -> %v:%d", srcIp, srcPort, dstIp, dstPort)
			return
		}

		p.setSourceIP(session.dstIp)
		p.setDestinationIP(session.srcIp)
		tp.setSourcePort(session.dstPort)
		tp.setDestinationPort(session.srcPort)

	} else {
		isNew, port := g.nat.newSession(srcIp, srcPort, dstIp, dstPort)
		if port <= 0 {
			log.Warning("create nat session fail,  %v:%d -> %v:%d", srcIp, srcPort, dstIp, dstPort)
			return
		}

		if isNew {
			if log.IsEnabledFor(logging.DEBUG) {
				log.Debug("tcp %v:%d -> %v:%d, relay: %d", srcIp, srcPort, dstIp, dstPort, port)
			}
		}

		p.setSourceIP(dstIp)
		p.setDestinationIP(g.relayIp)
		tp.setSourcePort(port)
		tp.setDestinationPort(g.relayPort)
	}

	tp.resetChecksum(p.pseudoSum())
	p.resetChecksum()

	g.ifce.Write(*p)
}

func (g *Gateway) handleICMP(p *ipv4Packet) {
	icmps := icmpPacket(p.payload())
	srcIp, dstIp := p.sourceIP(), p.destinationIP()

	if icmps.packetType() == icmp_request && icmps.code() == 0 {
		log.Debug("icmp request %v -> %v, icmp payload size: %d", srcIp, dstIp, icmps.dataLen())
		icmps.setPacketType(icmp_echo)

		p.setSourceIP(dstIp)
		p.setDestinationIP(srcIp)

		icmps.resetChecksum()
		p.resetChecksum()

		g.ifce.Write(*p)
	} else {
		log.Debug("icmp %v -> %v", srcIp, dstIp)
	}
}

func (g *Gateway) handleUDP(p *ipv4Packet) {
	up := udpPacket(p.payload())

	srcIp := p.sourceIP()
	dstIp := p.destinationIP()

	srcPort := up.sourcePort()
	dstPort := up.destinationPort()

	if srcPort == g.relayPort && g.relayIp.Equal(srcIp) {
		session := g.nat.getSession(dstPort)
		if session == nil {
			log.Warning("nat session not found, %v:%d -> %v:%d", srcIp, srcPort, dstIp, dstPort)
			return
		}

		p.setSourceIP(session.dstIp)
		p.setDestinationIP(session.srcIp)
		up.setSourcePort(session.dstPort)
		up.setDestinationPort(session.srcPort)

	} else {
		isNew, port := g.nat.newSession(srcIp, srcPort, dstIp, dstPort)
		if port <= 0 {
			log.Warning("create nat session fail,  %v:%d -> %v:%d", srcIp, srcPort, dstIp, dstPort)
			return
		}

		if isNew {
			if log.IsEnabledFor(logging.DEBUG) {
				log.Debug("udp %v:%d -> %v:%d, relay: %d", srcIp, srcPort, dstIp, dstPort, port)
			}
		}

		p.setSourceIP(dstIp)
		p.setDestinationIP(g.relayIp)
		up.setSourcePort(port)
		up.setDestinationPort(g.relayPort)
	}

	up.resetChecksum(p.pseudoSum())
	p.resetChecksum()

	g.ifce.Write(*p)
}

func (g *Gateway) handleTCPRelayConn(conn *net.TCPConn) {
	defer func() {
		if x := recover(); x != nil {
			log.Error("handle relay conn exception, %v", x)
		}
		conn.Close()
	}()

	conn.SetNoDelay(true)

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	remotePort := uint16(remoteAddr.Port)

	session := g.nat.getSession(remotePort)
	// log.Debug("remoteAddr: %v, session: %v", remoteAddr, session)

	if session == nil {
		log.Warning("nat session not found, %v->%v", conn.LocalAddr(), remoteAddr)
		return
	}

	if g.proxy == nil {
		log.Warning("gateway proxy dialer is nil")
		return
	}

	key := internal.GetRedisIpKey(session.dstIp.String())
	host, err := g.RedisClient.Get(key).Result()
	if err != nil {
		log.Warning("get redis domain fail %s, error: %v", key, err)
		return
	}

	target := fmt.Sprintf("%s:%d", host, session.dstPort)
	tunnel, err := g.dialer.Dial("tcp", target)
	if err != nil {
		log.Warning("dial %s by proxy %s error %v", target, g.proxy.String(), err)
		return
	}

	defer tunnel.Close()

	uploadChan := make(chan int64)
	downloadchan := make(chan int64)

	go forward(conn, tunnel.(*net.TCPConn), uploadChan)
	go forward(tunnel.(*net.TCPConn), conn, downloadchan)

	uploadBytes := <-uploadChan
	downloadBytes := <-downloadchan

	log.Debug("relay %s:%d request %s, upload: %d, download: %d",
		session.srcIp.String(), session.srcPort, target,
		uploadBytes, downloadBytes)
}

func (g *Gateway) handleUDPRelay(clientAddr *net.UDPAddr, packet []byte) {
	defer func() {
		if x := recover(); x != nil {
			log.Error("handle udp relay exception, %v", x)
		}
	}()

	tunnel := g.getUDPTunnel(clientAddr)
	if tunnel == nil {
		return
	}

	tunnel.SetDeadline(time.Now().Add(natSessionLife * time.Second))
	tunnel.Write(packet)
}

func (g *Gateway) getUDPTunnel(clientAddr *net.UDPAddr) *net.UDPConn {
	g.udpTunnelLock.Lock()
	defer g.udpTunnelLock.Unlock()

	port := uint16(clientAddr.Port)
	session := g.nat.getSession(port)
	if session == nil {
		return nil
	}

	tunnel := g.udpTunnels[clientAddr.String()]
	if tunnel != nil {
		return tunnel
	}

	realIp, err := g.getRealIp(session.dstIp.String())

	if err != nil {
		log.Warning("get real ip fail %v:%d, error: %s", session.dstIp, session.dstPort, err)
		return nil
	}

	log.Debug("get real ip: %s %s", session.dstIp.String(), realIp)

	target := &net.UDPAddr{
		IP:   net.ParseIP(realIp),
		Port: int(session.dstPort),
	}
	tunnel, err = net.DialUDP("udp", nil, target)
	if err != nil {
		log.Warning("dial %s error %v", target, err)
		return nil
	}
	log.Debug("udp create tunnel %s:%d -> %s:%d",
		clientAddr.IP.String(), clientAddr.Port, target.IP.String(), target.Port)
	g.udpTunnels[clientAddr.String()] = tunnel

	go func() {
		defer func() {
			g.udpTunnelLock.Lock()
			defer g.udpTunnelLock.Unlock()

			log.Debug("udp destroy tunnel %s:%d -> %s:%d",
				clientAddr.IP.String(), clientAddr.Port, target.IP.String(), target.Port)

			delete(g.udpTunnels, clientAddr.String())
			tunnel.Close()

		}()
		buf := make([]byte, mtu)
		for {
			n, err := tunnel.Read(buf)
			if err != nil {

				if e, ok := err.(*net.OpError); ok && e.Timeout() {
					break
				}

				log.Error("read data failed, %v", err)
				break
			}

			_, err = g.relayUDPServer.WriteToUDP(buf[:n], clientAddr)
			if err != nil {
				log.Error("response to client error, %v", err)
				break
			}
		}
	}()

	return tunnel
}

func (g *Gateway) getRealIp(dstIp string) (string, error) {
	realIpKey := internal.GetRedisRealIpKey(dstIp)
	realIp, err := g.RedisClient.Get(realIpKey).Result()
	if err != nil && realIp != "" {
		return realIp, nil
	}

	realIpQueryLock.Lock()
	defer realIpQueryLock.Unlock()

	// retry
	realIp, err = g.RedisClient.Get(realIpKey).Result()
	if err != nil && realIp != "" {
		return realIp, nil
	}

	ipKey := internal.GetRedisIpKey(dstIp)
	host, err := g.RedisClient.Get(ipKey).Result()
	if err != nil {
		return "", err
	}

	conn, err := g.dialer.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	m := new(dns.Msg)
	m.SetQuestion(fmt.Sprintf("%s.", host), dns.TypeA)
	m.RecursionDesired = true

	co := &dns.Conn{Conn: conn}
	defer co.Close()
	co.WriteMsg(m)
	r, err := co.ReadMsg()
	if err != nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", errors.New(fmt.Sprintf("query %s dns fail, code %d", host, r.Rcode))
	}

	var ttl uint32
	for _, a := range r.Answer {
		if v, ok := a.(*dns.A); ok {
			realIp = v.A.String()
			ttl = v.Hdr.Ttl
			break
		}
	}

	if realIp == "" {
		return "", errors.New(fmt.Sprintf("answer not found record type A, host: %s", host))
	}

	log.Debug("cache real ip query result, cache key: %s, mapping ip: %s, host: %s, realIp: %s",
		realIpKey, dstIp, host, realIp)

	g.RedisClient.SetNX(realIpKey, realIp, time.Duration(ttl)*time.Second)
	return realIp, nil
}

func (g *Gateway) subscribe() {
	channels := []string{
		internal.GetRedisNetworkChannelKey(),
		internal.GetRedisProxyChannelKey(),
	}
	log.Debug("subscribe channels: %s", strings.Join(channels, ", "))
	sub := g.RedisClient.Subscribe(channels...)
	for {
		message, err := sub.ReceiveMessage()
		if err != nil {
			log.Error("receive message error %v", err)
			continue
		}

		log.Info("receive message from channel %s with payload: %s", message.Channel, message.Payload)

		if err := g.loadConfig(); err != nil {
			log.Error("reload gateway config fail")
		} else {
			log.Debug("shutdown relay server")
			// restart the server
			g.relayTCPServer.Close()
			g.relayTCPServer = nil
			g.relayUDPServer.Close()
			g.relayUDPServer = nil
			time.Sleep(time.Second * 5)

			log.Debug("re-config tun ifce")
			g.configTun()

			log.Debug("start relay server")
			go g.relayTCPServe()
			go g.relayUDPServe()
		}
	}
}

func execCommand(name string, args string) error {
	log.Debug("execute cmd %s %s", name, args)
	return exec.Command(name, strings.Split(args, " ")...).Run()
}

func isIPv4Packet(packet *[]byte) bool {
	return ((*packet)[0] >> 4) == 4
}

func forward(src *net.TCPConn, dst *net.TCPConn, ch chan<- int64) {
	n, _ := io.Copy(dst, src)
	dst.CloseWrite()
	src.CloseRead()
	ch <- n
}
