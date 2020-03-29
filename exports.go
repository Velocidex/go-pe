package pe

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
)

func (self *IMAGE_NT_HEADERS) ExportDirectory(
	rva_resolver *RVAResolver) *IMAGE_EXPORT_DIRECTORY {
	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	offset := rva_resolver.GetFileAddress(dir.VirtualAddress())

	return self.Profile.IMAGE_EXPORT_DIRECTORY(self.Reader, int64(offset))
}

func (self *IMAGE_EXPORT_DIRECTORY) DLLName(rva_resolver *RVAResolver) string {
	offset := int64(rva_resolver.GetFileAddress(self.Name()))
	return ParseTerminatedString(self.Reader, offset)
}

func GetExports(nt_header *IMAGE_NT_HEADERS, rva_resolver *RVAResolver) []string {
	ed := nt_header.ExportDirectory(rva_resolver)

	result := make([]string, ed.NumberOfNames())
	startOfNamesOffset := rva_resolver.GetFileAddress(ed.AddressOfNames())

	for i := uint32(0); i < ed.NumberOfNames(); i++ {
		nameAddr := startOfNamesOffset + (i * 4)
		nameOffset := rva_resolver.GetFileAddress(
			ParseUint32(ed.Reader, int64(nameAddr)),
		)

		result[i] = ParseTerminatedString(ed.Reader, int64(nameOffset))
	}

	return result
}
