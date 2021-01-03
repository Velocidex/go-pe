package main

import (
	"encoding/json"
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"
)

var (
	messages_command      = app.Command("messages", "Extracts messages from PE file.")
	messages_command_file = messages_command.Arg("file", "").Required().
				OpenFile(os.O_RDONLY, 0600)
)

func doMessages() {
	reader, err := reader.NewPagedReader(*messages_command_file, 4096, 100)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*messages_command_file).Name(), err)

	pe_file, err := pe.NewPEFile(reader)
	kingpin.FatalIfError(err, "Can not open file %s: %v",
		(*messages_command_file).Name(), err)

	messages := pe_file.GetMessages()
	serialized, _ := json.MarshalIndent(messages, "", "  ")
	fmt.Println(string(serialized))
}
