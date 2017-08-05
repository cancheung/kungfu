package gateway

import "encoding/binary"

type tcpPacket []byte

func (p *tcpPacket) sourcePort() uint16 {
	return binary.BigEndian.Uint16((*p)[0:2])
}

func (p *tcpPacket) setSourcePort(port uint16) {
	binary.BigEndian.PutUint16(*p, port)
}

func (p *tcpPacket) destinationPort() uint16 {
	return binary.BigEndian.Uint16((*p)[2:4])
}

func (p *tcpPacket) setDestinationPort(port uint16) {
	binary.BigEndian.PutUint16((*p)[2:4], port)
}

func (p *tcpPacket) setChecksum(sum [2]byte) {
	(*p)[16] = sum[0]
	(*p)[17] = sum[1]
}

func (p *tcpPacket) checksum() uint16 {
	return binary.BigEndian.Uint16((*p)[16:18])
}

func (p *tcpPacket) resetChecksum(psum uint32) {
	p.setChecksum(zeroChecksum)
	p.setChecksum(checksum(psum, *p))
}
