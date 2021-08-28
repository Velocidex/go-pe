package pe

import "fmt"

const (
	IMAGE_DIRECTORY_ENTRY_IMPORT = 1
)

func (self *IMAGE_NT_HEADERS) ImportDirectory(
	rva_resolver *RVAResolver) []*IMAGE_IMPORT_DESCRIPTOR {
	result := []*IMAGE_IMPORT_DESCRIPTOR{}

	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)
	offset := rva_resolver.GetFileAddress(dir.VirtualAddress())
	for offset > 0 {
		desc := self.Profile.IMAGE_IMPORT_DESCRIPTOR(
			self.Reader, int64(offset))
		if desc.Name() == 0 && desc.Characteristics() == 0 {
			break
		}

		result = append(result, desc)
		if len(result) > MAX_IMPORT_TABLE_LENGTH {
			break
		}

		offset += uint32(desc.Size())
	}

	return result
}

func (self *IMAGE_IMPORT_DESCRIPTOR) DLLName(rva_resolver *RVAResolver) string {
	offset := int64(rva_resolver.GetFileAddress(self.Name()))
	result := ParseTerminatedString(self.Reader, offset)
	return result
}

func (self *IMAGE_IMPORT_DESCRIPTOR) Functions32(rva_resolver *RVAResolver) []string {
	result := []string{}

	offset := int64(rva_resolver.GetFileAddress(self.OriginalFirstThunk()))
	for {
		thunk := self.Profile.IMAGE_THUNK_DATA32(
			self.Reader, offset)

		if thunk.Function() == 0 {
			break
		}

		import_by_name := self.Profile.IMAGE_IMPORT_BY_NAME(
			self.Reader, int64(rva_resolver.GetFileAddress(
				thunk.AddressOfData())))

		if import_by_name.Offset != 0 {
			result = append(result, import_by_name.Name())
		} else {
			// If the import is by ordinal then encode it
			// as hex.
			result = append(result, fmt.Sprintf(
				"%#x", 0xFFFFFF&thunk.Ordinal()))
		}
		offset += int64(thunk.Size())

		// Keep the size resonable
		if len(result) > MAX_IMPORT_TABLE_LENGTH {
			break
		}
	}

	return result
}

func (self *IMAGE_IMPORT_DESCRIPTOR) Functions64(rva_resolver *RVAResolver) []string {
	result := []string{}

	offset := int64(rva_resolver.GetFileAddress(self.OriginalFirstThunk()))
	for {
		thunk := self.Profile.IMAGE_THUNK_DATA64(self.Reader, offset)
		if thunk.Function() == 0 {
			break
		}

		import_by_name := self.Profile.IMAGE_IMPORT_BY_NAME(
			self.Reader, int64(rva_resolver.GetFileAddress(
				uint32(thunk.AddressOfData()))))

		if import_by_name.Offset != 0 {
			result = append(result, import_by_name.Name())
		} else {
			// If the import is by ordinal then encode it
			// as hex.
			result = append(result, fmt.Sprintf(
				"%#x", 0xFFFFFF&thunk.Ordinal()))
		}
		offset += int64(thunk.Size())
		if len(result) > MAX_IMPORT_TABLE_LENGTH {
			break
		}
	}

	return result
}

func GetImports(nt_header *IMAGE_NT_HEADERS, rva_resolver *RVAResolver) []string {
	result := []string{}
	for _, desc := range nt_header.ImportDirectory(rva_resolver) {
		dll_name := desc.DLLName(rva_resolver)

		if nt_header.OptionalHeader().Magic() == 0x20b {
			for _, name := range desc.Functions64(rva_resolver) {
				result = append(result, dll_name+"!"+name)
			}
		} else {
			for _, name := range desc.Functions32(rva_resolver) {
				result = append(result, dll_name+"!"+name)
			}
		}
	}

	return result
}
