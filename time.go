package pe

import (
	"io"
	"time"
)

type UnixTimeStamp32 struct {
	time.Time
	Raw uint32
}

func (self *UnixTimeStamp32) DebugString() string {
	return self.String()
}

func (self *UnixTimeStamp32) String() string {
	result, _ := self.UTC().MarshalText()
	return string(result)
}

func (self *PeProfile) UnixTimeStamp32(reader io.ReaderAt, offset int64) *UnixTimeStamp32 {
	result := &UnixTimeStamp32{
		Raw: ParseUint32(reader, offset),
	}

	result.Time = time.Unix(int64(result.Raw), 0)
	return result
}
