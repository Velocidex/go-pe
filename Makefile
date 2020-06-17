all:
	go build -o cmd/peinfo cmd/*.go

generate:
	binparsegen conversion.spec.yaml > pe_gen.go

windows:
	GOOS=windows GOARCH=amd64  go build -o cmd/peinfo.exe cmd/*.go
