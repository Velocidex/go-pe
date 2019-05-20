package pe

import (
	"io"
	"time"
)

type UnixTimeStamp struct {
	time.Time
}

func (self *UnixTimeStamp) DebugString() string {
	return self.String()
}

func (self *UnixTimeStamp) String() string {
	result, _ := self.UTC().MarshalText()
	return string(result)
}

func (self *PeProfile) UnixTimeStamp(reader io.ReaderAt, offset int64) *UnixTimeStamp {
	timestamp := ParseUint64(reader, offset)
	return &UnixTimeStamp{time.Unix(int64(timestamp), 0)}
}
