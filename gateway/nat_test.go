package gateway

import (
	"github.com/yinheli/kungfu/internal"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestNat(t *testing.T) {
	n := newNat()

	srcIp := net.ParseIP("192.168.9.68")
	srcPort := uint16(5000)
	dstIp := net.ParseIP("10.85.0.2")
	dstPort := uint16(80)

	isNew, port := n.newSession(srcIp, srcPort, dstIp, dstPort)

	if !isNew {
		t.Fatal("should new")
	}

	if port < 0 {
		t.FailNow()
	}

	isNew2, port2 := n.newSession(srcIp, srcPort, dstIp, dstPort)
	if isNew2 {
		t.Fatal("should not new")
	}

	if port2 != port {
		t.Fatal("same param new session request, port should equal")
	}

	s := n.getSession(port)

	if !s.srcIp.Equal(srcIp) {
		t.Fatal("session srcIp should equal")
	}

	if !s.dstIp.Equal(dstIp) {
		t.Fatal("session dstIp should equal")
	}

	if s.srcPort != srcPort {
		t.Fatal("session srcPort should equal")
	}

	if s.dstPort != dstPort {
		t.Fatal("session dstPort should equal")
	}
}

func BenchmarkNat(b *testing.B) {
	runtime.GOMAXPROCS(10)

	n := newNat()

	minIp, maxIp, _ := internal.ParseNetwork("10.0.0.1/16")

	var ipIdx uint32

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ipx := atomic.AddUint32(&ipIdx, 1)
			_, port := n.newSession(
				internal.IntToIpv4((minIp+ipx)%maxIp),
				8080,
				internal.IntToIpv4((minIp+ipx)%maxIp),
				5000,
			)

			if port <= 0 {
				b.Fatal("new session fail")
				return
			}

			n.getSession(port)
		}
	})

	b.Logf("session count: %d", len(n.sessions))
}
