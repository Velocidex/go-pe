package pe

import "io"

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
