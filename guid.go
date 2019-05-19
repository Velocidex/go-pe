package pe

import "fmt"

func (self *CV_RSDS_HEADER) GUIDAge() string {
	guid := self.GUID()
	return fmt.Sprintf("%08X%04X%04X%16X%d",
		guid.Data1(), guid.Data2(), guid.Data3(),
		guid.Data4(), self.Age())
}
