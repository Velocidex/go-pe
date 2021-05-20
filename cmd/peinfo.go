package main

import (
	"encoding/json"
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"

	// Required to find utilities.
	_ "www.velocidex.com/golang/binparsergen"
)

var (
	app               = kingpin.New("go-pe", "PE parser and extractor.")
	info_command      = app.Command("info", "Displays info about a pe file.")
	info_command_file = info_command.Arg("file", "").Required().
				OpenFile(os.O_RDONLY, 0600)
)

func doInfo() {
	reader, err := reader.NewPagedReader(*info_command_file, 4096, 100)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*info_command_file).Name(), err)

	pe_file, err := pe.NewPEFile(reader)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*info_command_file).Name(), err)

	serialized, _ := json.MarshalIndent(pe_file, "", "  ")
	fmt.Println(string(serialized))
}

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))
	switch command {

	case info_command.FullCommand():
		doInfo()

	case messages_command.FullCommand():
		doMessages()

	case authenticode_command.FullCommand():
		doAuthenticode()

	case cat_command.FullCommand():
		doCat()
	}
}
