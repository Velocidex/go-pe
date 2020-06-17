package pe

import "fmt"

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
)

type IMAGE_EXPORT_DESCRIPTOR struct {
	Ordinal int
	Name    string
	RVA     int64
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

	number_of_names := int(desc.NumberOfNames())
	number_of_funcs := desc.NumberOfFunctions()

	ordinal_table := ParseArray_uint16(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfNameOrdinals())),
		number_of_names)

	// A list of RVAs to names
	name_table := ParseArray_uint32(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfNames())),
		number_of_names)

	func_table := ParseArray_uint32(self.Profile, self.Reader,
		int64(rva_resolver.GetFileAddress(desc.AddressOfFunctions())),
		int(number_of_funcs))

	seen := make(map[uint32]bool)

	for i := 0; i < number_of_names; i++ {
		name := ParseTerminatedString(self.Reader,
			int64(rva_resolver.GetFileAddress(name_table[i])))
		ordinal := ordinal_table[i]
		func_rva := uint32(0)

		if int(ordinal) < len(func_table) {
			func_rva = func_table[ordinal]
		}

		seen[uint32(ordinal)] = true

		result = append(result, &IMAGE_EXPORT_DESCRIPTOR{
			Ordinal: int(ordinal),
			Name:    name,
			RVA:     int64(func_rva),
		})
	}

	// Now list exported functions without a name (by ordinal)
	base := desc.Base()
	for i := uint32(0); i < number_of_funcs; i++ {
		ordinal := base + i
		_, pres := seen[ordinal]
		if !pres {
			seen[ordinal] = true
			result = append(result, &IMAGE_EXPORT_DESCRIPTOR{
				Ordinal: int(ordinal),
				RVA:     int64(func_table[i]),
			})
		}
	}

	return result
}

func (self *IMAGE_EXPORT_DIRECTORY) DLLName(rva_resolver *RVAResolver) string {
	offset := int64(rva_resolver.GetFileAddress(self.Name()))
	result := ParseTerminatedString(self.Reader, offset)
	return result
}

func GetExports(nt_header *IMAGE_NT_HEADERS, rva_resolver *RVAResolver) []string {
	result := []string{}

	desc := nt_header.ExportDirectory(rva_resolver)
	if desc == nil {
		// No Export Directory
		return nil
	}

	dll_name := desc.DLLName(rva_resolver)

	for _, desc := range nt_header.ExportTable(rva_resolver) {
		if desc.Name == "" {
			result = append(result, fmt.Sprintf("%s:#%d", dll_name, desc.Ordinal))
		} else {
			result = append(result, fmt.Sprintf("%s:%s", dll_name, desc.Name))
		}
	}

	return result
}
