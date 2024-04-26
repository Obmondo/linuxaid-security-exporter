export NAME=security-exporter
export RELEASE=1.0
export VERSION=1.0
## make sure that dist folder is created at root of project before building
export DIST=../../dist
export MAINTAINER=Rishikesh <rishikesh@enableit.dk>
export PREFIX=/opt/obmondo/bin/
SOURCES := security-exporter
GOBIN := $(shell realpath ../../bin)

packages: deb rpm mk-dist

mk-dist:
	@mkdir -p ../../dist

deb: mk-dist $(DIST)/$(NAME)_$(VERSION)_amd64.deb
$(DIST)/$(NAME)_$(VERSION)_amd64.deb:  security-exporter.service postinstall
	apt update
	apt install -y ruby
	gem install fpm
	apt install -y rpm
	fpm \
	--input-type dir \
	--output-type deb \
	--name $(NAME) \
	--package $(DIST) \
	--version $(VERSION) \
	--deb-systemd=security-exporter.service \
	--deb-systemd-enable \
	--deb-systemd-auto-start \
	--deb-systemd-restart-after-upgrade \
	--after-install postinstall \
	../../dist/security-exporter=/opt/obmondo/bin/security-exporter \
	../../config/config.local.yaml=/etc/$(NAME)/config.yaml

rpm: mk-dist $(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm
$(DIST)/$(NAME)-$(VERSION)-1.x86_64.rpm: security-exporter.service postinstall
	fpm \
	--input-type dir \
	--output-type rpm \
	--name $(NAME) \
	--package $(DIST) \
	--version $(VERSION) \
	--after-install postinstall \
	../../dist/security-exporter=/opt/obmondo/bin/security-exporter \
	security-exporter.service=/lib/systemd/system/ \
	../../config/config.local.yaml=/etc/$(NAME)/config.yaml
