package gateway

import (
	"net"
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
