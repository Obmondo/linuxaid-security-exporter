export NAME=obmondo-security-exporter
export RELEASE=1.0.4
export VERSION=1.0.4
## make sure that dist folder is created at root of project before building
export DIST=./dist
export MAINTAINER=Rishikesh <rishikesh@enableit.dk>
export PREFIX=/opt/obmondo/bin/
SOURCES := security-exporter



build:
	CGO_ENABLED=0 go build -a -v -ldflags="-extldflags=-static" -o $(DIST)/$(NAME) cmd/main.go
test:
	@go test ./...
test-v:
	@go test -v ./...
release: test build


packages: build mk-dist deb rpm  clean

mk-dist:
	@mkdir -p ./dist

deb: mk-dist $(DIST)/$(NAME)_$(VERSION)_amd64.deb
$(DIST)/$(NAME)_$(VERSION)_amd64.deb:  $(NAME).service postinstall
	fpm \
	--input-type dir \
	--output-type deb \
	--name $(NAME) \
	--package $(DIST) \
	--version $(VERSION) \
	--deb-systemd=$(NAME).service \
	--deb-systemd-enable \
	--deb-systemd-auto-start \
	--deb-systemd-restart-after-upgrade \
	--after-install postinstall \
	$(DIST)/$(NAME)=/opt/obmondo/bin/$(NAME) \
	./config/config.local.yaml=/etc/$(NAME)/config.yaml

rpm: mk-dist $(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm
$(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm: $(NAME).service postinstall
	fpm \
	--input-type dir \
	--output-type rpm \
	--name $(NAME) \
	--package $(DIST) \
	--version $(VERSION) \
	--after-install postinstall \
	$(DIST)/$(NAME)=/opt/obmondo/bin/$(NAME) \
	$(NAME).service=/lib/systemd/system/ \
	./config/config.local.yaml=/etc/$(NAME)/config.yaml

clean:
	rm $(DIST)/$(NAME)
