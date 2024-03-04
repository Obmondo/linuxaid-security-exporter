package extracter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	expectedDebianOutputForExtractAppWithSecurityUpdate = []string{"docker-compose-plugin", "netbird", "netbird-ui", "teamviewer"}
	testInputDebianForExtractAppWithSecurityUpdate      = `Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
The following packages were automatically installed and are no longer required:
  irqbalance libboost-iostreams1.74.0 libgfapi0 libgfrpc0 libgfxdr0 libglusterfs0 libpython3.11 libpython3.11-dev python3.11-dev
Use 'sudo apt autoremove' to remove them.
The following packages will be upgraded:
  docker-compose-plugin netbird netbird-ui teamviewer
4 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst docker-compose-plugin [2.24.5-1~ubuntu.22.04~jammy] (2.24.6-1~ubuntu.22.04~jammy Docker CE:jammy [amd64])
Inst netbird [0.26.0] (0.26.2 Artifactory:stable [amd64])
Inst netbird-ui [0.26.0] (0.26.2 Artifactory:stable [amd64])
Inst teamviewer [15.50.5] (15.51.5 TeamViewer:stable [amd64])
Conf docker-compose-plugin (2.24.6-1~ubuntu.22.04~jammy Docker CE:jammy [amd64])
Conf netbird (0.26.2 Artifactory:stable [amd64])
Conf netbird-ui (0.26.2 Artifactory:stable [amd64])
Conf teamviewer (15.51.5 TeamViewer:stable [amd64])
`
)

var testInputDebianForExtractCVEFromChangelog = `Get:1 https://changelogs.ubuntu.com curl 8.5.0-2ubuntu2 Changelog [112 kB]
curl (8.5.0-2ubuntu2) noble; urgency=medium

  * SECURITY UPDATE: OCSP verification bypass with TLS session reuse
    - debian/patches/CVE-2024-0853.patch: when verifystatus fails, remove
      session id from cache in lib/vtls/openssl.c.
    - CVE-2024-0853

 -- Marc Deslauriers <marc.deslauriers@ubuntu.com>  Wed, 31 Jan 2024 11:09:34 -0500

curl (8.5.0-2ubuntu1) noble; urgency=medium

  * Merge with Debian unstable (LP: #2045886). Remaining changes:
    - debian/control: Don't build-depend on python3-impacket on i386
      so we can drop it (and its dependencies) from the i386 partial port.
      It's only used for the tests, which do not block the build in any case.

 -- Danilo Egea Gondolfo <danilo.egea.gondolfo@canonical.com>  Tue, 02 Jan 2024 09:32:27 +0000

curl (8.5.0-2) unstable; urgency=medium

  * d/p/openldap_fix_an_LDAP_crash.patch: New patch to fix ldap segfault
    (closes: #1057855)

 -- Samuel Henrique <samueloph@debian.org>  Fri, 29 Dec 2023 15:34:11 -0300

curl (8.5.0-1) unstable; urgency=medium

  [ Samuel Henrique ]
  * New upstream version 8.5.0
    - Fix CVE-2023-46218: cookie mixed case PSL bypass (closes: #1057646)
    - Fix CVE-2023-46219: HSTS long file name clears contents (closes: #1057645)
  * d/rules: Use pkg-info.mk instead of dpkg-parsechangelog for DEB_VERSION
  * d/p/90_gnutls.patch: Update patch
  * d/p/dist_add_tests_errorcodes_pl_to_the_tarball.patch: Upstream patch to
    fix tests
  * d/p/add_errorcodes_upstream_file.patch: Include missing file from upstream
    tarball

  [ Carlos Henrique Lima Melara ]
  * d/control: change Maintainer field to curl packaging team
  * d/README.Debian: add readme to explain curl's team creation
  * d/control: add myself to Uploaders

 -- Samuel Henrique <samueloph@debian.org>  Wed, 06 Dec 2023 20:15:49 +0000

curl (8.4.0-2ubuntu1) noble; urgency=medium

  * Merge from Debian unstable (LP: #2039798). Remaining changes:
    - debian/control: Don't build-depend on python3-impacket on i386
      so we can drop it (and its dependencies) from the i386 partial port.
      It's only used for the tests, which do not block the build in any case.
  * Drop patches for CVEs fixed upstream:
    - debian/patches/CVE-2023-38039.patch
    - debian/patches/CVE-2023-38545.patch
    - debian/patches/CVE-2023-38546.patch
  * Drop delta merged in Debian:
    - debian/tests/control
    - debian/tests/curl-ldapi-test

curl (8.4.0-1ubuntu1) noble; urgency=medium

  * Merge from Debian unstable (LP: #2039798). Remaining changes:

 -- Danilo Egea Gondolfo <danilo.egea.gondolfo@canonical.com>  Wed, 01 Nov 2023 12:06:23 +0000
Fetched 112 kB in 2s (47.1 kB/s)`

var expectedDebianOutputForExtractCVE = []string{"CVE-2024-0853", "CVE-2023-46219", "CVE-2023-46218", "CVE-2023-38546", "CVE-2023-38545", "CVE-2023-38039"}

func TestDebianExtractAppWithSecurityUpdate(t *testing.T) {
	assert := require.New(t)
	debainExtractor := newDebianExtractor()
	output := debainExtractor.ExtractAppWithSecurityUpdate(testInputDebianForExtractAppWithSecurityUpdate)

	assert.Equal(len(expectedDebianOutputForExtractAppWithSecurityUpdate), len(output), "lenght of extracted output is not same")
	for i, app := range expectedDebianOutputForExtractAppWithSecurityUpdate {
		assert.Equal(app, output[i].Name)
	}
}

func TestDebianExtractCVENumberForGivenChangelog(t *testing.T) {
	assert := require.New(t)
	debainExtractor := newDebianExtractor()
	outputs := debainExtractor.ExtractCVENumberForGivenChangelog(testInputDebianForExtractCVEFromChangelog, "8.4.0-1")
	assert.NotEmpty(outputs)

	assert.Equal(expectedDebianOutputForExtractCVE, outputs)
}
