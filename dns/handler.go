package dns

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/yinheli/kungfu/internal"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const DEFAULT_TTL = time.Duration(time.Hour * 3)
const DNS_SERVER_NAME = "kungfu-dns-server-helps-you-automatic-climb-the-wall."

type handler struct {
	server     *Server
	client     *dns.Client
	nameserver []string

	lock sync.Mutex
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if x := recover(); x != nil {
			log.Error("ServeDNS error", x)
			log.Error("request:\n%v", r)
			log.Error("request Extra :\n%v", r.Extra)
			log.Error("stack %s", string(debug.Stack()))

			dns.HandleFailed(w, r)
		}
	}()

	if r == nil {
		return
	}

	question := r.Question[0]

	var msg *dns.Msg
	var err error

	if question.Qtype == dns.TypePTR {
		msg, err = h.resolveInternalPTR(r)
	} else {
		isIPV4A := isIPV4TypeAQuery(&question)
		if isIPV4A {
			msg, err = h.resolveInternal(r)
		} else {
			msg, err = h.resolveUpstream(r)
		}
	}

	if err != nil {
		log.Error("process resolve error: %v", err)
	}

	// log
	if msg != nil && msg.Rcode != dns.RcodeSuccess {
		log.Debug("resolve remote addr: %s, qname: %s rcode: %d",
			w.RemoteAddr().String(), question.Name, msg.Rcode)
	}

	if err != nil || msg == nil {
		dns.HandleFailed(w, r)
	} else {
		w.WriteMsg(msg)
	}

}

func isIPV4TypeAQuery(q *dns.Question) bool {
	return q.Qclass == dns.ClassINET && q.Qtype == dns.TypeA
}

func (h *handler) queryDomainCache(r *dns.Msg) (*dns.Msg, error) {
	qname := r.Question[0].Name
	redis := h.server.RedisClient
	qnameKey := internal.GetRedisDomainKey(qname)

	ttl, err := redis.TTL(qnameKey).Result()
	if err != nil {
		log.Error("redis check %s error %v", qname, err)
		return nil, err
	}

	if ttl > 1 {
		ip, err := redis.Get(qnameKey).Result()
		if err != nil {
			log.Error("redis get %s error %v", qname, err)
			return nil, err
		}

		msg := new(dns.Msg)
		msg.SetReply(r)
		a := newARecord(qname, net.ParseIP(ip), uint32(ttl.Seconds()))
		msg.Answer = append(msg.Answer, a)
		log.Debug("internal resolve %s result: %s, ttl: %d", qname, ip, a.Hdr.Ttl)
		return msg, nil
	}

	return nil, errors.New("cache not found")
}

func (h *handler) resolveInternal(r *dns.Msg) (*dns.Msg, error) {
	msg, err := h.queryDomainCache(r)
	if err != nil {
		return nil, err
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	// recheck
	msg, _ = h.queryDomainCache(r)
	if msg != nil {
		return msg, nil
	}

	qname := r.Question[0].Name
	redis := h.server.RedisClient

	if !h.isDomainInGfwlist(qname) {
		return h.resolveUpstream(r)
	}

	qnameKey := internal.GetRedisDomainKey(qname)

	currentIpKey := internal.GetRedisKey("current-ip")

	ipInt, err := redis.Incr(currentIpKey).Result()
	if err != nil {
		return nil, err
	}

	ipValue := (h.server.minIp + uint32(ipInt)) % h.server.maxIp

	ip := internal.IntToIpv4(ipValue)

	ipStr := ip.String()

	qnameIpKey := internal.GetRedisIpKey(ipStr)

	success, err := redis.SetNX(qnameIpKey, strings.TrimSuffix(qname, "."), DEFAULT_TTL).Result()
	if err != nil {
		return nil, err
	}

	if !success {
		return nil, errors.New(fmt.Sprintf("update ip cache fail: duplicate key: %s, %s", qnameIpKey, qname))
	}

	success, err = redis.SetNX(qnameKey, ipStr, DEFAULT_TTL).Result()
	if err != nil {
		redis.Del(qnameIpKey)
		return nil, err
	}

	if !success {
		redis.Del(qnameIpKey)
		return nil, errors.New(fmt.Sprintf("update domain cache fail: duplicate key: %s, %s", qnameKey, ipStr))
	}

	msg = new(dns.Msg)
	msg.SetReply(r)
	a := newARecord(qname, ip, uint32(DEFAULT_TTL.Seconds()))
	msg.Answer = append(msg.Answer, a)
	log.Debug("internal *new resolve %s result: %s, ttl: %d", qname, ip, a.Hdr.Ttl)
	return msg, nil
}

func (h *handler) resolveInternalPTR(r *dns.Msg) (*dns.Msg, error) {
	qname := r.Question[0].Name

	if h.server.arpaContains(&qname) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		ptr := new(dns.PTR)
		ptr.Hdr = dns.RR_Header{
			Name:   dns.Fqdn(qname),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		ptr.Ptr = DNS_SERVER_NAME
		msg.Answer = append(msg.Answer, ptr)
		return msg, nil
	}

	return h.resolveUpstream(r)
}

func (h *handler) resolveUpstream(r *dns.Msg) (*dns.Msg, error) {
	qname := r.Question[0].Name
	qtype := dns.Type(r.Question[0].Qtype).String()

	var err error
	var rtt time.Duration
	for _, ns := range h.nameserver {
		r, rtt, err = h.client.Exchange(r, ns)
		if err != nil {
			log.Error("resolve upstream %s on %s qtype: %s error %v", qname, ns, qtype, err)
			continue
		}

		if r.Rcode == dns.RcodeServerFailure {
			log.Error("resolve upstream %s on %s qtype: %s fail code %d", qname, ns, qtype, r.Rcode)
			continue
		}

		log.Debug("resolve upstream %s on %s qtype: %s, code: %d, rtt: %d", qname, ns, qtype, r.Rcode, rtt)
		break
	}

	return r, err
}

func (h *handler) isDomainInGfwlist(domain string) bool {
	if domain == "." {
		return false
	}

	domain = strings.TrimSuffix(domain, ".")

	if h.isSingleDomainInGfwList(domain) {
		return true
	}

	ds := strings.Split(domain, ".")

	n := len(ds)
	if n == 1 {
		return false
	}

	for i, j := 1, n-1; i < j; i += 1 {
		s := strings.Join(ds[i:], ".")
		if h.isSingleDomainInGfwList(s) {
			return true
		}
	}

	return false
}

func (h *handler) isSingleDomainInGfwList(domain string) bool {
	key := internal.GetRedisProxyDomainSetKey()
	v, err := h.server.RedisClient.SIsMember(key, domain).Result()
	if err != nil {
		log.Warning("check single domain in proxy set error, domain %s, %v", domain, err)
		return false
	}

	return v
}

func newARecord(qname string, ip net.IP, ttl uint32) *dns.A {
	a := new(dns.A)
	a.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(qname),
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	a.A = ip
	return a
}
