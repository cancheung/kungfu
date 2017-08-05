package gateway

func checksum(s uint32, b []byte) (answer [2]byte) {
	s += sum(b)
	s = (s >> 16) + (s & 0xffff)
	s += s >> 16
	s = ^s
	answer[0] = byte(s >> 8)
	answer[1] = byte(s)
	return
}

func sum(b []byte) uint32 {
	var s uint32

	n := len(b)
	for i := 0; i < n; i = i + 2 {
		s += uint32(b[i]) << 8
		if i+1 < n {
			s += uint32(b[i+1])
		}
	}
	return s
}
