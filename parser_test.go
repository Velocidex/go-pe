package pe

import (
	"bytes"
	"io"
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

func TestImphash(t *testing.T) {
	// This file has some imports as ordinals
	// Test fix for https://github.com/Velocidex/velociraptor/issues/1755
	fd, err := os.Open("testdata/notepad.exe")
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
	g.AssertJson(t, "TestImphash", result)
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

func TestResourceStringParser(t *testing.T) {
	profile := NewPeProfile()
	b1 := []byte{15, 0, 0, 0, 1, 0, byte('t'), 0, byte('e'), 0, byte('s'), 0, byte('t'), 0, 0, 0, byte('X'), 0, 0, 0}
	b2 := []byte{20, 0, 2, 0, 1, 0, byte('t'), 0, byte('e'), 0, byte('s'), 0, byte('t'), 0, 0, 0, byte('y'), 0, 0, 0}
	rs1 := &ResourceString{
		Reader:  io.NewSectionReader(bytes.NewReader(b1), 0, int64(len(b1))),
		Profile: profile,
	}
	rs2 := &ResourceString{
		Reader:  io.NewSectionReader(bytes.NewReader(b2), 0, int64(len(b2))),
		Profile: profile,
	}
	assert.Equal(t, rs1.Key(), "test")
	assert.Equal(t, rs1.Value(), "")
	assert.Equal(t, rs2.Key(), "test")
	assert.Equal(t, rs2.Value(), "y")
}
