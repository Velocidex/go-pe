package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"www.velocidex.com/golang/binparsergen/reader"
	pe "www.velocidex.com/golang/go-pe"

	// Required to find utilities.
	_ "www.velocidex.com/golang/binparsergen"
)

func Fatalf(err error, format string, args ...interface{}) {
	if err != nil {
		fmt.Printf(format+"\n", args...)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("You must specify one or more exe files.")
		os.Exit(1)
	}

	for _, filename := range flag.Args() {
		fd, err := os.Open(filename)
		Fatalf(err, "Can not open file %s: %v", filename, err)

		reader, err := reader.NewPagedReader(fd, 4096, 100)
		Fatalf(err, "Can not open file %s: %v", filename, err)

		pe_file, err := pe.NewPEFile(reader)
		Fatalf(err, "Can not open file %s: %v", filename, err)

		serialized, _ := json.MarshalIndent(pe_file, "", "  ")
		fmt.Println(string(serialized))
	}
}
