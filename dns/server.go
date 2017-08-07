package dns

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis"
	"github.com/miekg/dns"
	"github.com/yinheli/kungfu"
	"github.com/yinheli/kungfu/internal"
)

var (
	log = kungfu.GetLog()
)

// Server is the dns server
type Server struct {
	RedisClient *redis.Client

	minIp         uint32
	maxIp         uint32
	localArpaLock sync.RWMutex
	localArpa     map[string]bool
	handler       *handler
}

// Start the dns server
func (server *Server) Start() {

	network, err := server.RedisClient.Get(internal.GetRedisNetworkKey()).Result()
	if err != nil {
		log.Error("get network config error, %v", err)
		return
	}

	minIp, maxIp, err := internal.ParseNetwork(network)
	if err != nil {
		log.Error("parse network error %v", err)
		return
	}

	server.minIp = minIp
	server.maxIp = maxIp

	log.Info("network config: %s, ip pool min: %s, max: %s, pool size: %d",
		network,
		internal.IntToIpv4(minIp+1),
		internal.IntToIpv4(maxIp-1),
		maxIp-minIp-1)

	upstreamNameserver, err := server.RedisClient.Get(internal.GetRedisUpstreamNameserverKey()).Result()
	if err != nil {
		log.Error("get upstream name server error, %v", err)
		return
	}

	var nameserver []string
	for _, n := range strings.Split(upstreamNameserver, ",") {
		n = strings.TrimSpace(n)
		if len(n) > 0 {
			n = fmt.Sprintf("%s:%d", n, 53)
			nameserver = append(nameserver, n)
		}
	}

	log.Info("upstream nameservers: %s", upstreamNameserver)
	log.Debug("parsed upstream nameservers: %v", nameserver)

	server.initLocalArpa()

	timeout := time.Duration(time.Second * 10)

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	server.handler = &handler{
		server:     server,
		client:     client,
		nameserver: nameserver,
	}

	go func() {
		udpServer := &dns.Server{
			Net:          "udp4",
			Addr:         "0.0.0.0:53",
			Handler:      server.handler,
			ReadTimeout:  timeout,
			WriteTimeout: timeout,
		}

		log.Debug("start dns udp server")
		err = udpServer.ListenAndServe()
		if err != nil {
			log.Error("start dns udp server fail, %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		tcpServer := &dns.Server{
			Net:          "tcp4",
			Addr:         "0.0.0.0:53",
			Handler:      server.handler,
			ReadTimeout:  timeout,
			WriteTimeout: timeout,
		}

		log.Debug("start dns tcp server")
		err = tcpServer.ListenAndServe()
		if err != nil {
			log.Error("start dns tcp server fail, %v", err)
			os.Exit(1)
		}
	}()

	server.subscribe()
}

func (server *Server) initLocalArpa() {
	server.localArpa = make(map[string]bool)

	server.localArpaLock.Lock()
	defer server.localArpaLock.Unlock()

	addr, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("get local interface addr error, %v", err)
		return
	}

	for _, a := range addr {
		ip, _, _ := net.ParseCIDR(a.String())
		ip = ip.To4()
		if ip == nil {
			continue
		}
		arpa, err := dns.ReverseAddr(ip.String())
		if err != nil {
			log.Warning("parse ip arpa fail %s, %v", ip.String(), err)
			continue
		}

		server.localArpa[arpa] = true
	}
}

func (server *Server) arpaContains(qname *string) bool {
	server.localArpaLock.RLock()
	defer server.localArpaLock.RUnlock()
	_, ok := server.localArpa[*qname]
	return ok
}

func (server *Server) subscribe() {
	networkChannelKey := internal.GetRedisNetworkChannelKey()
	log.Debug("subscribe network-channel, %s", networkChannelKey)
	sub := server.RedisClient.Subscribe(networkChannelKey)
	for {
		message, err := sub.ReceiveMessage()
		if err != nil {
			log.Error("receive message error %v", err)
			continue
		}

		network := message.Payload

		log.Info("receive network channel message payload: %s", network)

		minIp, maxIp, err := internal.ParseNetwork(network)
		if err != nil {
			log.Error("parse network error %v", err)
			continue
		}

		server.minIp = minIp
		server.maxIp = maxIp

		log.Info("update network config: %s, ip pool min: %s, max: %s, pool size: %d",
			network,
			internal.IntToIpv4(minIp+1),
			internal.IntToIpv4(maxIp-1),
			maxIp-minIp-1)

		ip, _, _ := net.ParseCIDR(network)
		arpa, _ := dns.ReverseAddr(ip.String())

		server.localArpaLock.Lock()
		server.localArpa[arpa] = true
		server.localArpaLock.Unlock()
	}
}
