package pe

import (
	"context"
	"fmt"
	"io"
	"sync"
)

var (
	pool = sync.Pool{
		New: func() interface{} {
			buffer := make([]byte, 32*1024)
			return &buffer
		},
	}
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

func (self *ReaderWrapper) CopyRange(
	ctx context.Context,
	writer io.Writer, start, end int64) error {
	if end-start < 0 || end-start > GetHashSizeLimit() {
		return fmt.Errorf("Range size exceeded: %#x", end-start)
	}

	self.offset = start
	CopyN(ctx, writer, self, end-self.offset)

	return nil
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

func CopyN(ctx context.Context, dst io.Writer, src io.Reader, count int64) (
	n int, err error) {
	offset := 0
	buff := pool.Get().(*[]byte)
	defer pool.Put(buff)

	for count > 0 {
		select {
		case <-ctx.Done():
			return offset, nil

		default:
			read_buff := *buff
			if count < int64(len(read_buff)) {
				read_buff = read_buff[:count]
			}

			n, err = src.Read(read_buff)
			if err != nil && err != io.EOF {
				return offset, err
			}

			if n == 0 {
				return offset, nil
			}

			_, err = dst.Write(read_buff[:n])
			if err != nil {
				return offset, err
			}
			offset += n
			count -= int64(n)
		}
	}
	return offset, nil
}
