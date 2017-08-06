package gateway

import "encoding/binary"

type udpPacket []byte

func (p *udpPacket) sourcePort() uint16 {
	return binary.BigEndian.Uint16(*p)
}

func (p *udpPacket) setSourcePort(port uint16) {
	binary.BigEndian.PutUint16(*p, port)
}

func (p *udpPacket) destinationPort() uint16 {
	return binary.BigEndian.Uint16((*p)[2:])
}

func (p *udpPacket) setDestinationPort(port uint16) {
	binary.BigEndian.PutUint16((*p)[2:4], port)
}

func (p *udpPacket) setChecksum(sum [2]byte) {
	(*p)[6] = sum[0]
	(*p)[7] = sum[1]
}

func (p *udpPacket) checksum() uint16 {
	return binary.BigEndian.Uint16((*p)[6:8])
}

func (p *udpPacket) resetChecksum(psum uint32) {
	p.setChecksum(zeroChecksum)
	p.setChecksum(checksum(psum, *p))
}
