package pe

func RoundUpToWordAlignment(offset int64) int64 {
	if offset%4 > 0 {
		offset += 4 - offset%4
	}
	return offset
}
