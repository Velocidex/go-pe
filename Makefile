all:
	go build -o cmd/peinfo cmd/*.go

windows:
	GOOS=windows GOARCH=amd64  go build -o cmd/peinfo.exe cmd/*.go
