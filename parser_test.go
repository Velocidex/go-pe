package pe

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/sebdah/goldie"
)

func TestForwarder(t *testing.T) {
	fd, err := os.Open("testdata/dmdskres.dll")
	assert.NoError(t, err)

	pe_file, err := NewPEFile(fd)
	assert.NoError(t, err)

	serialized, _ := json.MarshalIndent(pe_file, "", "  ")
	goldie.Assert(t, "TestForwarder", serialized)

}
