package pe

import "io"

type OffsetReader struct {
	reader io.ReaderAt
	offset int64
	length int64
}

func (self OffsetReader) ReadAt(buff []byte, off int64) (int, error) {
	to_read := int64(len(buff))
	if off+to_read > self.length {
		to_read = self.length - off
	}

	if to_read < 0 {
		return 0, nil
	}
	return self.reader.ReadAt(buff, off+self.offset)
}
