// Parse the debug headers - extracts the GUID and PDB information (RSDS).

package pe

import (
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

var (
	PE_DEBUG *bool
)

func (self *IMAGE_NT_HEADERS) DebugDirectory(
	rva_resolver *RVAResolver) *IMAGE_DEBUG_DIRECTORY {
	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG)
	offset := rva_resolver.GetFileAddress(dir.VirtualAddress())
	return self.Profile.IMAGE_DEBUG_DIRECTORY(self.Reader, int64(offset))
}

func (self *IMAGE_NT_HEADERS) RSDS(
	rva_resolver *RVAResolver) *CV_RSDS_HEADER {
	debug_directory := self.DebugDirectory(rva_resolver)
	return self.Profile.CV_RSDS_HEADER(self.Reader, int64(
		rva_resolver.GetFileAddress(
			debug_directory.AddressOfRawData())))
}

// A prefixed string contains a length followed by the UTF16 string.
func (self *PrefixedString) String() string {
	return ParseUTF16String(
		self.Reader,
		self.Profile.Off_PrefixedString__Buffer+self.Offset,
		int64(self.Length()))
}

func DebugPrint(fmt_str string, v ...interface{}) {
	if PE_DEBUG == nil {
		// os.Environ() seems very expensive in Go so we cache
		// it.
		for _, x := range os.Environ() {
			if strings.HasPrefix(x, "PE_DEBUG=") {
				value := true
				PE_DEBUG = &value
				break
			}
		}
	}

	if PE_DEBUG == nil {
		value := false
		PE_DEBUG = &value
	}

	if *PE_DEBUG {
		fmt.Printf(fmt_str, v...)
	}
}

func Debug(arg interface{}) {
	spew.Dump(arg)
}
