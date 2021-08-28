package pe

import (
	"io"
)

func RoundUpToWordAlignment(offset int64) int64 {
	if offset%4 > 0 {
		offset += 4 - offset%4
	}
	return offset
}

type ReaderWrapper struct {
	reader io.ReaderAt
	offset int64
}

func (self *ReaderWrapper) Read(p []byte) (n int, err error) {
	n, err = self.reader.ReadAt(p, self.offset)
	self.offset += int64(n)
	return n, err
}

func (self *ReaderWrapper) Seek(offset int64) {
	self.offset = offset
}

func (self *ReaderWrapper) CopyRange(writer io.Writer, start, end int64) {
	self.offset = start
	io.CopyN(writer, self, end-self.offset)
}

func (self *ReaderWrapper) Tell() int64 {
	return self.offset
}

func NewReaderWrapper(reader io.ReaderAt) *ReaderWrapper {
	return &ReaderWrapper{
		reader: reader,
	}
}

func CapUint64(v uint64, max uint64) uint64 {
	if v > max {
		return max
	}
	return v
}

func CapUint32(v uint32, max uint32) uint32 {
	if v > max {
		return max
	}
	return v
}

func CapUint16(v uint16, max uint16) uint16 {
	if v > max {
		return max
	}
	return v
}

func CapInt64(v int64, max int64) int64 {
	if v < 0 {
		return 0
	}
	if v > max {
		return max
	}
	return v
}

func CapInt32(v int32, max int32) int32 {
	if v < 0 {
		return 0
	}

	if v > max {
		return max
	}
	return v
}
