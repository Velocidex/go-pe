package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Velocidex/ordereddict"
	kingpin "github.com/alecthomas/kingpin/v2"
	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

var (
	authenticode_command      = app.Command("authenticode", "Displays authenticode information about the file")
	authenticode_command_file = authenticode_command.Arg("file", "").Required().
					OpenFile(os.O_RDONLY, 0600)

	authenticode_command_verify = authenticode_command.Flag("hash", "Calculated hash").Bool()
)

func doAuthenticode() {
	reader, err := reader.NewPagedReader(*authenticode_command_file, 4096, 100)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*authenticode_command_file).Name(), err)

	pe_file, err := pe.NewPEFile(reader)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*authenticode_command_file).Name(), err)

	dict := ordereddict.NewDict()
	authenticode_info, err := pe.ParseAuthenticode(pe_file)
	if err != nil {
		dict.Set("Error", fmt.Sprintf("Can not parse authenticode_info: %v", err))
	} else {
		dict = pe.PKCS7ToOrderedDict(authenticode_info)
	}

	ctx := context.Background()
	if *authenticode_command_verify {
		res, _ := pe_file.CalcHashToDict(ctx)
		dict.Set("CalculatedHash", res)
	}

	serialized, _ := json.MarshalIndent(dict, "", "  ")
	fmt.Println(string(serialized))
}
