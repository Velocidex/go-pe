package pe

import (
	"errors"
	"io"
)

// Exported API

type Section struct {
	Perm       string `json:"perm"`
	Name       string `json:"name"`
	FileOffset int64  `json:"file_offset"`
	VMA        int64  `json:"vma"`
	Size       int64  `json:"size"`
}

type PEFile struct {
	nt_header *IMAGE_NT_HEADERS

	// Used to resolve RVA to file offsets.
	rva_resolver *RVAResolver

	// The file offset to the resource section.
	resource_base int64

	Machine       string     `json:"machine"`
	TimeDateStamp string     `json:"TimeDateStamp"`
	GUIDAge       string     `json:"GUIDAge"`
	PDB           string     `json:"PDB"`
	Sections      []*Section `json:"sections"`

	VersionInformation map[string]string `json:"version_information"`
}

func GetVersionInformation(
	nt_header *IMAGE_NT_HEADERS,
	rva_resolver *RVAResolver,
	resource_base int64) map[string]string {
	result := make(map[string]string)

	// Find the RT_VERSION resource.
	for _, entry := range nt_header.
		ResourceDirectory(rva_resolver).Entries() {

		if entry.NameString(resource_base) == "RT_VERSION" {
			for _, child := range entry.Traverse(resource_base) {
				vs_info := child.Profile.VS_VERSIONINFO(
					child.Reader,
					int64(rva_resolver.GetFileAddress(
						child.OffsetToData())))

				for _, child := range vs_info.Children() {
					for _, string_table := range child.StringTable() {
						for _, resource_string := range string_table.
							ResourceStrings() {
							result[resource_string.Key()] = resource_string.Value()
						}

					}
				}

			}
		}

	}

	return result
}

func NewPEFile(reader io.ReaderAt) (*PEFile, error) {
	profile := NewPeProfile()
	dos_header := profile.IMAGE_DOS_HEADER(reader, 0)
	if dos_header.E_magic() != 0x5a4d {
		return nil, errors.New("Invalid IMAGE_DOS_HEADER")
	}

	nt_header := dos_header.NTHeader()
	if nt_header.Signature() != 0x4550 {
		return nil, errors.New("Invalid IMAGE_NT_HEADERS")
	}

	rva_resolver := NewRVAResolver(nt_header)

	// Get the base address of the resource section.
	resource_section := nt_header.SectionByName(".rsrc")
	resource_base := int64(resource_section.PointerToRawData())

	file_header := nt_header.FileHeader()
	rsds := nt_header.RSDS(rva_resolver)

	result := &PEFile{
		nt_header:     nt_header,
		rva_resolver:  rva_resolver,
		resource_base: resource_base,
		Machine:       file_header.Machine().Name,
		TimeDateStamp: file_header.TimeDateStamp().String(),
		GUIDAge:       rsds.GUIDAge(),
		PDB:           rsds.Filename(),
		VersionInformation: GetVersionInformation(
			nt_header, rva_resolver, resource_base),
	}

	for _, section := range nt_header.Sections() {
		result.Sections = append(result.Sections, &Section{
			Perm:       section.Permissions(),
			Name:       section.Name(),
			FileOffset: int64(section.PointerToRawData()),
			VMA:        int64(section.VirtualAddress()),
		})

	}

	return result, nil
}
