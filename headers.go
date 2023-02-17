package pe

import (
	"io"
)

func (self *IMAGE_DOS_HEADER) NTHeader() *IMAGE_NT_HEADERS {
	return self.Profile.IMAGE_NT_HEADERS(
		self.Reader, int64(self.E_lfanew())+self.Offset)
}

func (self *IMAGE_NT_HEADERS) Sections() []*IMAGE_SECTION_HEADER {
	result := []*IMAGE_SECTION_HEADER{}

	// The sections start immediately after the OptionalHeader:
	offset := int64(self.FileHeader().SizeOfOptionalHeader()) +
		self.OptionalHeader().Offset

	number_of_sections := CapUint16(self.FileHeader().NumberOfSections(),
		MAX_NUMBER_OF_SECTIONS)

	for i := 0; i < int(number_of_sections); i++ {
		section := self.Profile.IMAGE_SECTION_HEADER(
			self.Reader, offset)
		if section.Characteristics() > 0 {
			result = append(result, section)
		}
		offset += int64(section.Size())
	}

	return result
}

func (self *IMAGE_NT_HEADERS) SectionByName(name string) *IMAGE_SECTION_HEADER {
	// The sections start immediately after the OptionalHeader:
	offset := int64(self.FileHeader().SizeOfOptionalHeader()) +
		self.OptionalHeader().Offset

	for i := 0; i < int(self.FileHeader().NumberOfSections()); i++ {
		section := self.Profile.IMAGE_SECTION_HEADER(
			self.Reader, offset)
		if section.Name() == name {
			return section
		}

		offset += int64(section.Size())
	}

	return &IMAGE_SECTION_HEADER{Profile: self.Profile, Reader: self.Reader}
}

func (self *IMAGE_SECTION_HEADER) Permissions() string {
	characteristics := self.Characteristics()

	result := ""
	if characteristics&0x20000000 > 0 {
		result += "x"
	} else {
		result += "-"
	}

	if characteristics&0x40000000 > 0 {
		result += "r"
	} else {
		result += "-"
	}

	if characteristics&0x80000000 > 0 {
		result += "w"
	} else {
		result += "-"
	}

	return result
}

func (self *IMAGE_SECTION_HEADER) Data() io.ReaderAt {
	return OffsetReader{
		reader: self.Reader,
		offset: int64(self.PointerToRawData()),
		length: int64(self.SizeOfRawData()),
	}
}

func (self *IMAGE_NT_HEADERS) DataDirectory(index int64) *IMAGE_DATA_DIRECTORY {
	optional_header := self.OptionalHeader()
	directory_offset := optional_header.Offset +
		self.Profile.Off_IMAGE_OPTIONAL_HEADER_DataDirectory
	if optional_header.Magic() == 0x20b {
		directory_offset = optional_header.Offset +
			self.Profile.Off_IMAGE_OPTIONAL_HEADER64_DataDirectory
	}

	size_of_image_data_dir := int64((&IMAGE_DATA_DIRECTORY{}).Size())
	image_data_directory := self.Profile.IMAGE_DATA_DIRECTORY(
		self.Reader, directory_offset+
			index*size_of_image_data_dir)

	return image_data_directory
}
