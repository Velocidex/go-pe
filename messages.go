package pe

import (
	"strings"
)

// References: https://github.com/nsacyber/Windows-Event-Log-Messages/blob/master/welm/WelmLibrary/EventMessageFile.cs

func (self *MESSAGE_RESOURCE_DATA) Blocks() []*MESSAGE_RESOURCE_BLOCK {
	return ParseArray_MESSAGE_RESOURCE_BLOCK(
		self.Profile,
		self.Reader,
		self.Profile.Off_MESSAGE_RESOURCE_DATA__Blocks+self.Offset,
		int(CapUint32(self.NumberOfBlocks(), MAX_RESOURCE_BLOCKS)))
}

func (self *MESSAGE_RESOURCE_DATA) Messages() []*Message {
	result := []*Message{}

	for _, block := range self.Blocks() {
		result = append(result, block.Messages()...)
	}

	return result
}

type Message struct {
	Id      int64
	EventId int
	Message string
}

// Each block contains a list of entries.
func (self *MESSAGE_RESOURCE_BLOCK) Messages() []*Message {
	result := []*Message{}
	offset := int64(self.OffsetToEntries())
	for i := self.LowId(); i <= self.HighId(); i++ {
		// Reserved bit 28
		is_reserved := ((i >> 28) & 1) > 0

		// Customer event is bit 29
		is_customer := ((i >> 29) & 1) > 0

		// https://github.com/nsacyber/Windows-Event-Log-Messages.git
		// not a Microsoft event from observation, these looks
		// like random string resources so far it seems safe
		// to discard these as not being events only Windows
		// 10 1607 it made a difference of removing ~2000
		// "events" from classicevents results.
		if !is_customer && is_reserved {
			continue
		}

		item := self.Profile.MESSAGE_RESOURCE_ENTRY(
			self.Reader, offset)

		// Bottom 16 bits are the event ID. We dont care about
		// the rest.
		event_id := i & 0xFFFF

		// We dont really know what all the bits in the Id
		// mean so we will just store it as well and maybe
		// figure it out later.
		result = append(result, &Message{
			Id:      int64(i),
			EventId: int(event_id),
			Message: item.Message()})

		if len(result) > MAX_MESSAGES {
			break
		}

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
			CapInt64(int64(self.Length()), MAX_MESSAGE_LENGTH))

	case 1: // UnicodeFlag
		result = ParseUTF16String(
			self.Reader,
			self.Profile.Off_MESSAGE_RESOURCE_ENTRY_Text+self.Offset,
			CapInt64(int64(self.Length()), MAX_MESSAGE_LENGTH))
	}

	return strings.Split(result, "\x00")[0]

}
