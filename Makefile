build:
	CGO_ENABLED=0 go build -a -v -ldflags="-extldflags=-static" -o dist/security-exporter cmd/main.go
test:
	go test ./...
test-v:
	go test -v ./...
release: test build
	cd bin/release && make packages
clean:
	rm ./dist/security-exporter
