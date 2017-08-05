package gateway

import (
	"fmt"
	"github.com/go-redis/redis"
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
	"time"
)

const (
	tun_name = "tun-kungfu-01"
	mtu      = 1500
)

var (
	log = kungfu.GetLog()
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
}

func (g *Gateway) Serve() {

	err := g.loadConfig()
	if err != nil {
		return
	}

	g.nat = newNat()

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
		log.Warning("get redis domain fail %s", key)
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

// TODO finish tunnel
func (g *Gateway) handleUDPRelay(clientAddr *net.UDPAddr, packet []byte) {
	defer func() {
		if x := recover(); x != nil {
			log.Error("handle udp relay exception, %v", x)
		}
	}()

	port := uint16(clientAddr.Port)
	session := g.nat.getSession(port)
	if session == nil {
		return
	}

	key := internal.GetRedisIpKey(session.dstIp.String())
	host, err := g.RedisClient.Get(key).Result()
	if err != nil {
		log.Warning("get redis domain fail %s", key)
		return
	}

	target := fmt.Sprintf("%s:%d", host, session.dstPort)
	conn, err := net.Dial("udp4", target)
	if err != nil {
		log.Warning("dial %s error %v", target, err)
		return
	}
	defer conn.Close()

	conn.Write(packet)
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
