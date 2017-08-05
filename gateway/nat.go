package gateway

import (
	"fmt"
	"github.com/yinheli/kungfu/internal"
	"net"
	"sync"
	"time"
)

const (
	natClearupMinInterval = 300
	natSessionLife        = 600
	natSuggestCount       = 10000
)

var (
	natLock      sync.RWMutex
	localAddr, _ = net.ResolveTCPAddr("tcp", "localhost:0")
)

type nat struct {
	sessions         map[uint16]*natSession
	portMap          map[uint64]uint16
	clearUpThreshold int
	lastClearUpTime  int64
}

type natSession struct {
	srcIp   net.IP
	dstIp   net.IP
	srcPort uint16
	dstPort uint16
	touch   int64
}

func newNat() *nat {
	return &nat{
		sessions:         make(map[uint16]*natSession, natSuggestCount),
		portMap:          make(map[uint64]uint16, natSuggestCount),
		clearUpThreshold: int(float64(natSuggestCount) * 0.7),
		lastClearUpTime:  time.Now().Unix(),
	}
}

func (n *nat) getSession(port uint16) *natSession {
	natLock.RLock()
	defer natLock.RUnlock()

	s := n.sessions[port]
	if s != nil {
		s.touch = time.Now().Unix()
	}
	return s
}

func (n *nat) newSession(srcIp net.IP, srcPort uint16, dstIp net.IP, dstPort uint16) (bool, uint16) {
	now := time.Now().Unix()
	n.triggerClearUpSession(now)

	natLock.Lock()
	defer natLock.Unlock()

	addrInt := addrToInt(srcIp, srcPort)
	if port, ok := n.portMap[addrInt]; ok {
		return false, port
	}

	newPort := n.getAvailablePort()

	if newPort < 0 {
		return false, newPort
	}

	n.sessions[newPort] = &natSession{
		srcIp:   srcIp,
		dstIp:   dstIp,
		srcPort: srcPort,
		dstPort: dstPort,
		touch:   now,
	}
	n.portMap[addrInt] = newPort

	return true, newPort
}

func (n *nat) getAvailablePort() uint16 {
	ln, err := net.ListenTCP("tcp4", localAddr)
	if err != nil {
		log.Error("get available port fail, %v", err)
		return 0
	}
	defer ln.Close()

	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func (n *nat) triggerClearUpSession(now int64) {
	if !n.isReadyClearUp(now) {
		return
	}

	// do clear up
	go func() {
		natLock.Lock()
		defer natLock.Unlock()

		if !n.isReadyClearUp(now) {
			return
		}

		log.Debug("start clear up nat session, session count: %d", len(n.sessions))
		for port, session := range n.sessions {
			if now-session.touch > natSessionLife {
				addrInt := addrToInt(session.srcIp, session.srcPort)
				delete(n.portMap, addrInt)
				delete(n.sessions, port)
			}
		}
		n.lastClearUpTime = now
		log.Debug("clear up nat session, finished, session count: %d", len(n.sessions))
	}()
}

func (n *nat) isReadyClearUp(now int64) bool {
	if now-n.lastClearUpTime < natClearupMinInterval {
		return false
	}
	return len(n.sessions) > n.clearUpThreshold
}

func (s *natSession) String() string {
	return fmt.Sprintf("src: %v:%d, dst: %v:%d, touched: %s",
		s.srcIp, s.srcPort, s.dstIp, s.dstPort,
		time.Unix(s.touch, 0).Format("2006-01-02 15:04:05"))
}

func addrToInt(ip net.IP, port uint16) uint64 {
	return uint64(internal.Ipv4ToInt(ip)) + uint64(port)
}
