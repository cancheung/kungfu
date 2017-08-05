package gateway

import (
	"encoding/binary"
	"net"
)

var zeroChecksum = [2]byte{0x00, 0x00}

const (
	icmp = 0x01
	tcp  = 0x06
	udp  = 0x11
)

type ipv4Packet []byte

func (p *ipv4Packet) totalLen() uint16 {
	return binary.BigEndian.Uint16((*p)[2:])
}

func (p *ipv4Packet) headerLen() uint16 {
	return uint16((*p)[0]&0xf) * 4
}

func (p *ipv4Packet) dataLen() uint16 {
	return p.totalLen() - p.headerLen()
}

func (p *ipv4Packet) payload() []byte {
	return (*p)[p.headerLen():p.totalLen()]
}

func (p *ipv4Packet) protocol() byte {
	return (*p)[9]
}

func (p *ipv4Packet) sourceIP() net.IP {
	return net.IPv4((*p)[12], (*p)[13], (*p)[14], (*p)[15]).To4()
}

func (p *ipv4Packet) setSourceIP(ip net.IP) {
	copy((*p)[12:16], []byte(ip.To4()))
}

func (p *ipv4Packet) destinationIP() net.IP {
	return net.IPv4((*p)[16], (*p)[17], (*p)[18], (*p)[19]).To4()
}

func (p *ipv4Packet) setDestinationIP(ip net.IP) {
	copy((*p)[16:20], []byte(ip.To4()))
}

func (p *ipv4Packet) checksum() uint16 {
	return binary.BigEndian.Uint16((*p)[10:12])
}

func (p *ipv4Packet) setChecksum(sum [2]byte) {
	(*p)[10] = sum[0]
	(*p)[11] = sum[1]
}

func (p *ipv4Packet) resetChecksum() {
	p.setChecksum(zeroChecksum)
	p.setChecksum(checksum(0, (*p)[:p.headerLen()]))
}

func (p *ipv4Packet) pseudoSum() uint32 {
	sum := sum((*p)[12:20])
	sum += uint32(p.protocol())
	sum += uint32(p.dataLen())
	return sum
}
