package gateway

import "encoding/binary"

type icmpPacket []byte

const (
	icmp_echo    = 0x0
	icmp_request = 0x8
)

func (p *icmpPacket) packetType() byte {
	return (*p)[0]
}

func (p *icmpPacket) setPacketType(t byte) {
	(*p)[0] = t
}

func (p *icmpPacket) code() byte {
	return (*p)[1]
}

func (p *icmpPacket) dataLen() uint16 {
	return uint16((len(*p)) - 8)
}

func (p *icmpPacket) checksum() uint16 {
	return binary.BigEndian.Uint16((*p)[2:])
}

func (p *icmpPacket) setChecksum(sum [2]byte) {
	(*p)[2] = sum[0]
	(*p)[3] = sum[1]
}

func (p *icmpPacket) resetChecksum() {
	p.setChecksum(zeroChecksum)
	p.setChecksum(checksum(0, *p))
}
