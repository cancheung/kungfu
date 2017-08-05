package internal

import "net"

func Ipv4ToInt(ip net.IP) uint32 {
	i := ip.To4()
	if i == nil {
		return 0
	}

	v := uint32(i[0]) << 24
	v += uint32(i[1]) << 16
	v += uint32(i[2]) << 8
	v += uint32(i[3])

	return v
}

func IntToIpv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
