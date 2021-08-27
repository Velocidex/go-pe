package pe

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
)

type IMAGE_EXPORT_DESCRIPTOR struct {
	Ordinal   int
	Name      string
	RVA       int64
	Forwarder string
	DLLName   string
}

/* Is the virtual address within the export directory.

   https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only

   Each entry in the export address table is a field that uses one of
   two formats in the following table. If the address specified is not
   within the export section (as defined by the address and length
   that are indicated in the optional header), the field is an export
   RVA, which is an actual address in code or data. Otherwise, the
   field is a forwarder RVA, which names a symbol in another DLL.
*/
func IsInExportDir(dir *IMAGE_DATA_DIRECTORY, va uint32) bool {
	start := dir.VirtualAddress()
	return va > start && va < start+dir.DirSize()
}

func (self *IMAGE_NT_HEADERS) ExportDirectory(
	rva_resolver *RVAResolver) *IMAGE_EXPORT_DIRECTORY {

	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if dir.DirSize() == 0 {
		// No Export Directory
		return nil
	}

	offset := rva_resolver.GetFileAddress(dir.VirtualAddress())
	return self.Profile.IMAGE_EXPORT_DIRECTORY(
		self.Reader, int64(offset))
}

func (self *IMAGE_NT_HEADERS) ExportTable(
	rva_resolver *RVAResolver) []*IMAGE_EXPORT_DESCRIPTOR {
	result := []*IMAGE_EXPORT_DESCRIPTOR{}
	desc := self.ExportDirectory(rva_resolver)
	if desc == nil {
		return nil
	}

	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if dir.DirSize() == 0 {
		return nil
	}

	dll_name := ""
	if !IsInExportDir(dir, desc.Name()) {
		dll_name = desc.DLLName(rva_resolver)
	}

	// Keep number_of_names reasonable
	number_of_names := int(CapUint32(
		desc.NumberOfNames(), MAX_IMPORT_TABLE_LENGTH))

	number_of_funcs := int(CapUint32(
		desc.NumberOfFunctions(), MAX_IMPORT_TABLE_LENGTH))

	ordinal_table := ParseArray_uint16(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfNameOrdinals())),
		number_of_names)

	// A list of RVAs to names
	name_table := ParseArray_uint32(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfNames())),
		number_of_names)

	func_table := ParseArray_uint32(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfFunctions())),
		number_of_funcs)

	seen := make(map[uint32]bool)

	// Get forwarders: Each entry in the export address table is
	// a field that uses one of two formats in the following
	// table. If the address specified is not within the export
	// section (as defined by the address and length that are
	// indicated in the optional header), the field is an export
	// RVA, which is an actual address in code or data. Otherwise,
	// the field is a forwarder RVA, which names a symbol in
	// another DLL.
	for i, func_addr := range func_table {
		if IsInExportDir(dir, func_addr) {
			if i >= len(ordinal_table) {
				continue
			}

			ordinal := ordinal_table[i]
			seen[uint32(ordinal)] = true

			name := ParseTerminatedString(self.Reader,
				int64(rva_resolver.GetFileAddress(func_addr)))
			result = append(result, &IMAGE_EXPORT_DESCRIPTOR{
				Ordinal:   int(ordinal),
				Name:      name,
				Forwarder: name,
				DLLName:   dll_name,
			})
		}
	}

	for i := 0; i < number_of_names; i++ {
		name := ParseTerminatedString(self.Reader,
			int64(rva_resolver.GetFileAddress(name_table[i])))
		ordinal := uint32(ordinal_table[i])
		func_rva := uint32(0)

		if int(ordinal) < len(func_table) {
			func_rva = func_table[ordinal]
		}

		_, pres := seen[ordinal]
		if pres {
			continue
		}
		seen[ordinal] = true

		result = append(result, &IMAGE_EXPORT_DESCRIPTOR{
			Ordinal: int(ordinal),
			Name:    name,
			DLLName: dll_name,
			RVA:     int64(func_rva),
		})
	}

	// Now list exported functions without a name (by ordinal)
	if len(func_table) > 0 {
		base := desc.Base()
		for i := 0; i < len(func_table)-1; i++ {
			ordinal := base + uint32(i)
			_, pres := seen[ordinal]
			if !pres {
				seen[ordinal] = true
				result = append(result, &IMAGE_EXPORT_DESCRIPTOR{
					Ordinal: int(ordinal),
					DLLName: dll_name,
					RVA:     int64(func_table[i]),
				})
			}
		}
	}

	return result
}

func (self *IMAGE_EXPORT_DIRECTORY) DLLName(rva_resolver *RVAResolver) string {
	offset := int64(rva_resolver.GetFileAddress(self.Name()))
	result := ParseTerminatedString(self.Reader, offset)
	return result
}
