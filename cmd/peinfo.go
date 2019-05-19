package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/pprof"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"

	// Required to find utilities.
	_ "www.velocidex.com/golang/binparsergen"
)

var (
	app = kingpin.New("peinfo",
		"A tool for printing information about pe files.")

	command_file_arg = app.Arg(
		"file", "The pe file to inspect",
	).Required().OpenFile(os.O_RDONLY, os.FileMode(0666))

	profile_flag = app.Flag(
		"profile", "Write profiling information to this file.").String()
)

func doParse() {
	reader, err := reader.NewPagedReader(*command_file_arg, 4096, 100)
	kingpin.FatalIfError(err, "NewPagedReader")

	pe_file, err := pe.NewPEFile(reader)
	kingpin.FatalIfError(err, "NewPeProfile")

	serialized, _ := json.MarshalIndent(pe_file, "", "  ")
	fmt.Println(string(serialized))

}

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *profile_flag != "" {
		f2, err := os.Create(*profile_flag)
		kingpin.FatalIfError(err, "Profile file.")

		pprof.StartCPUProfile(f2)
		defer pprof.StopCPUProfile()

	}

	doParse()
}
