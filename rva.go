package pe

// An RVA resolver maps a VirtualAddress to a file physical
// address. When the physical file is mapped into memory, sections in
// the file are mapped at different memory addresses. Internally the
// PE file contains pointers to those virtual addresses. This means we
// need to convert these pointers to mapped memory back into the file
// so we can read their data. The RVAResolver is responsible for this
// - it is populated from the header's sections.
type Run struct {
	VirtualAddress  uint32
	VirtualEnd      uint32
	PhysicalAddress uint32
}

type RVAResolver struct {
	// For now very simple O(n) search.
	Runs      []*Run
	ImageBase uint64
	Is64Bit   bool
}

func (self *RVAResolver) GetFileAddress(offset uint32) uint32 {
	for _, run := range self.Runs {
		if offset >= run.VirtualAddress &&
			offset < run.VirtualEnd {
			return offset - run.VirtualAddress + run.PhysicalAddress
		}
	}

	return 0
}

func NewRVAResolver(header *IMAGE_NT_HEADERS) *RVAResolver {
	result := &RVAResolver{}
	optional_header := header.OptionalHeader()

	if optional_header.Magic() == 0x20b {
		// It is a 64 bit header
		optional_header64 := header.Profile.IMAGE_OPTIONAL_HEADER64(
			optional_header.Reader, optional_header.Offset)
		result.ImageBase = optional_header64.ImageBase()
		result.Is64Bit = true
	} else {
		result.ImageBase = uint64(header.OptionalHeader().ImageBase())
	}

	for _, section := range header.Sections() {
		if section.SizeOfRawData() == 0 {
			continue
		}

		run := &Run{
			VirtualAddress:  section.VirtualAddress(),
			VirtualEnd:      section.VirtualAddress() + section.SizeOfRawData(),
			PhysicalAddress: section.PointerToRawData(),
		}

		result.Runs = append(result.Runs, run)
	}

	return result
}
