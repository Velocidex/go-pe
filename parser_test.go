package pe

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/pkcs7"
	"github.com/alecthomas/assert"
	"github.com/sebdah/goldie/v2"
	"www.velocidex.com/golang/binparsergen/reader"
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

func TestAuthenticode(t *testing.T) {
	fd, err := os.Open("testdata/acpiex.sys")
	assert.NoError(t, err)

	reader, err := reader.NewPagedReader(fd, 4096, 100)
	assert.NoError(t, err)

	pe_file, err := NewPEFile(reader)
	assert.NoError(t, err)

	authenticode_info, err := ParseAuthenticode(pe_file)
	assert.NoError(t, err)

	result := PKCS7ToOrderedDict(authenticode_info).
		Set("CalculatedHash", pe_file.CalcHashToDict())

	g := goldie.New(t, goldie.WithFixtureDir("fixtures"),
		goldie.WithNameSuffix(".golden"),
		goldie.WithDiffEngine(goldie.ColoredDiff))
	g.AssertJson(t, "TestAuthenticode", result)
}

func TestResources(t *testing.T) {
	fd, err := os.Open("testdata/notepad.exe")
	assert.NoError(t, err)

	reader, err := reader.NewPagedReader(fd, 4096, 100)
	assert.NoError(t, err)

	pe_file, err := NewPEFile(reader)
	assert.NoError(t, err)

	result := ordereddict.NewDict().
		Set("VersionInformation", pe_file.VersionInformation()).
		Set("Resources", pe_file.Resources())

	g := goldie.New(t, goldie.WithFixtureDir("fixtures"),
		goldie.WithNameSuffix(".golden"),
		goldie.WithDiffEngine(goldie.ColoredDiff))
	g.AssertJson(t, "TestResources", result)
}

func TestCatParser(t *testing.T) {
	fd, err := os.Open("testdata/ntexe.cat")
	assert.NoError(t, err)

	data, err := ioutil.ReadAll(fd)
	assert.NoError(t, err)

	pkcs7_obj, err := pkcs7.Parse(data)
	assert.NoError(t, err)

	dict := PKCS7ToOrderedDict(pkcs7_obj)

	g := goldie.New(t, goldie.WithFixtureDir("fixtures"),
		goldie.WithNameSuffix(".golden"),
		goldie.WithDiffEngine(goldie.ColoredDiff))
	g.AssertJson(t, "TestCatalog", dict)
}

func TestUTFParser(t *testing.T) {
	en := []uint8{72, 0, 101, 0, 108, 0, 108, 0, 111, 0, 87, 0, 111, 0, 114, 0, 108, 0, 100, 0, 0, 0, 74, 0, 0, 0}
	zh := []uint8{96, 79, 125, 89, 22, 78, 76, 117, 0, 0, 0, 0, 74, 0, 0, 0}

	assert.Equal(t, ParseTerminatedUTF16String(bytes.NewReader(en), 0), "HelloWorld")
	assert.Equal(t, ParseTerminatedUTF16String(bytes.NewReader(zh), 0), "你好世界")
}
