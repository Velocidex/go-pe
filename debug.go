// Parse the debug headers - extracts the GUID and PDB information (RSDS).

package pe

import (
	"fmt"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

var (
	PE_DEBUG bool
)

func (self *IMAGE_NT_HEADERS) DebugDirectory(
	rva_resolver *RVAResolver) (*IMAGE_DEBUG_DIRECTORY, error) {
	dir := self.DataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG)
	offset, err := rva_resolver.GetFileAddress(dir.VirtualAddress())
	if err != nil {
		return nil, err
	}
	return self.Profile.IMAGE_DEBUG_DIRECTORY(self.Reader, int64(offset)), nil
}

func (self *IMAGE_NT_HEADERS) RSDS(
	rva_resolver *RVAResolver) (*CV_RSDS_HEADER, error) {
	debug_directory, err := self.DebugDirectory(rva_resolver)
	if err != nil {
		return nil, err
	}

	file_address, err := rva_resolver.GetFileAddress(
		debug_directory.AddressOfRawData())
	if err != nil {
		return nil, err
	}

	return self.Profile.CV_RSDS_HEADER(self.Reader, int64(
		file_address)), nil
}

// A prefixed string contains a length followed by the UTF16 string.
func (self *PrefixedString) String() string {
	return ParseUTF16String(
		self.Reader,
		self.Profile.Off_PrefixedString__Buffer+self.Offset,
		int64(self.Length()*2))
}

func init() {
	// os.Environ() seems very expensive in Go so we cache it.
	for _, x := range os.Environ() {
		if strings.HasPrefix(x, "PE_DEBUG=") {
			PE_DEBUG = true
			return
		}
	}
}

func DebugPrint(fmt_str string, v ...interface{}) {
	if PE_DEBUG {
		fmt.Printf(fmt_str, v...)
	}
}

type DebugStringer interface {
	DebugString() string
}

func Debug(arg interface{}) {
	if PE_DEBUG {
		d, ok := arg.(DebugStringer)
		if ok {
			fmt.Println(d.DebugString())
			return
		}

		spew.Dump(arg)
	}
}
