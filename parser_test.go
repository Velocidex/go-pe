package pe

import (
	"os"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/alecthomas/assert"
	"github.com/sebdah/goldie/v2"
)

func TestForwarder(t *testing.T) {
	fd, err := os.Open("testdata/dmdskres.dll")
	assert.NoError(t, err)

	pe_file, err := NewPEFile(fd)
	assert.NoError(t, err)

	result := ordereddict.NewDict().
		Set("FileHeader", pe_file.FileHeader).
		Set("Sections", pe_file.Sections).
		Set("VersionInformation", pe_file.VersionInformation()).
		Set("Imports", pe_file.Imports()).
		Set("Exports", pe_file.Exports()).
		Set("Forwards", pe_file.Forwards()).
		Set("ImpHash", pe_file.ImpHash())

	g := goldie.New(t, goldie.WithFixtureDir("fixtures"),
		goldie.WithNameSuffix(".golden"),
		goldie.WithDiffEngine(goldie.ColoredDiff))
	g.AssertJson(t, "TestForwarder", result)
}
