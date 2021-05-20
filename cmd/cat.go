package main

import (
	"io/ioutil"
	"os"

	"github.com/Velocidex/pkcs7"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	pe "www.velocidex.com/golang/go-pe"
)

var (
	cat_command      = app.Command("cat", "Displays information about catalog files.")
	cat_command_file = cat_command.Arg("file", "").Required().OpenFile(os.O_RDONLY, 0600)
)

func doCat() {
	data, err := ioutil.ReadAll(*cat_command_file)
	kingpin.FatalIfError(err, "Can not open file")

	pkcs7, err := pkcs7.Parse(data)
	kingpin.FatalIfError(err, "Can not open file")

	pe.Debug(pkcs7)
}
