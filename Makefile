PATH := ./bin:$(PATH)
export NAME=obmondo-security-exporter
export VERSION=1.1.5
## make sure that dist folder is created at root of project before building
export DIST=./dist
export MAINTAINER=Rishikesh <rishikesh@enableit.dk>
export PREFIX=/opt/obmondo/bin/
SOURCES := security-exporter

build:
	mkdir -p $(DIST)/amd64 && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -v -ldflags="-extldflags=-static" -o $(DIST)/amd64/$(NAME) cmd/main.go
	mkdir -p $(DIST)/arm64 && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -a -v -ldflags="-extldflags=-static" -o $(DIST)/arm64/$(NAME) cmd/main.go

test:
	@go test ./...
test-v:
	@go test -v ./...
release: test build

packages: test build mk-dist deb rpm deb_arm clean

mk-dist:
	@mkdir -p ./dist

deb: $(DIST)/$(NAME)_$(VERSION)_amd64.deb
$(DIST)/$(NAME)_$(VERSION)_amd64.deb: $(NAME).service postinstall
	ARCHITECTURE=amd64 TARGET=deb fpm-single-file     \
	--prefix ''                                       \
	--deb-systemd=$(NAME).service                     \
	--deb-systemd-restart-after-upgrade               \
	--after-install postinstall                       \
	$(DIST)/amd64/$(NAME)=/opt/obmondo/bin/           \
	./config/config.local.yaml=/etc/$(NAME)/config.yaml

deb_arm: $(DIST)/$(NAME)_$(VERSION)_arm64.deb
$(DIST)/$(NAME)_$(VERSION)_arm64.deb: $(NAME).service postinstall
	ARCHITECTURE=arm64 TARGET=deb fpm-single-file     \
	--prefix ''                                       \
	--deb-systemd=$(NAME).service                     \
	--deb-systemd-restart-after-upgrade               \
	--after-install postinstall                       \
	$(DIST)/arm64/$(NAME)=/opt/obmondo/bin/           \
	./config/config.local.yaml=/etc/$(NAME)/config.yaml

rpm: $(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm
$(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm: $(NAME).service postinstall
	ARCHITECTURE=amd64 TARGET=rpm fpm-single-file     \
	--prefix ''                                       \
	--after-install postinstall                       \
	$(DIST)/amd64/$(NAME)=/opt/obmondo/bin/           \
	$(NAME).service=/lib/systemd/system/              \
	./config/config.local.yaml=/etc/$(NAME)/config.yaml

clean:
	rm -rf $(DIST)/amd64 $(DIST)/arm64
