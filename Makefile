build:
	go build -v -o dist/security-exporter cmd/main.go
test:
	go test ./...
test-v:
	go test -v ./...
release: test build
	cd bin/release && make packages
