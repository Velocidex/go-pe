package pe

import "strings"

// References: https://github.com/nsacyber/Windows-Event-Log-Messages/blob/master/welm/WelmLibrary/EventMessageFile.cs

func (self *MESSAGE_RESOURCE_DATA) Blocks() []*MESSAGE_RESOURCE_BLOCK {
	return ParseArray_MESSAGE_RESOURCE_BLOCK(
		self.Profile,
		self.Reader,
		self.Profile.Off_MESSAGE_RESOURCE_DATA__Blocks+self.Offset,
		int(self.NumberOfBlocks()))
}

func (self *MESSAGE_RESOURCE_DATA) Messages() []*Message {
	result := []*Message{}

	for _, block := range self.Blocks() {
		result = append(result, block.Messages()...)
	}

	return result
}

type Message struct {
	EventId int
	Message string
}

// Each block contains a list of entries.
func (self *MESSAGE_RESOURCE_BLOCK) Messages() []*Message {
	result := []*Message{}

	offset := int64(self.OffsetToEntries())
	for i := self.LowId(); i <= self.HighId(); i++ {
		item := self.Profile.MESSAGE_RESOURCE_ENTRY(
			self.Reader, offset)

		// Bottom 16 bits are the event ID. We dont care about
		// the rest.
		event_id := i & 0xFFFF

		result = append(result, &Message{
			EventId: int(event_id),
			Message: item.Message()})

		offset += int64(item.Length())
	}

	return result
}

func (self *MESSAGE_RESOURCE_ENTRY) Message() string {
	result := ""

	switch self.Flags() {
	case 0: // AnsiFlag
		result = ParseString(
			self.Reader,
			self.Profile.Off_MESSAGE_RESOURCE_ENTRY_Text+self.Offset,
			int64(self.Length()))

	case 1: // UnicodeFlag
		result = ParseUTF16String(
			self.Reader,
			self.Profile.Off_MESSAGE_RESOURCE_ENTRY_Text+self.Offset,
			int64(self.Length()))

	}

	return strings.Split(result, "\x00")[0]

}
