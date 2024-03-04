package extracter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testRHELInputForExtractCVEFromChangeLog = `Loaded plugins: changelog, fastestmirror, ovl
Loading mirror speeds from cached hostfile
 * base: centos.excellmedia.net
 * extras: centos.excellmedia.net
 * updates: centos.excellmedia.net

Listing all changelogs

==================== Installed Packages ====================
curl-7.29.0-59.el7.x86_64                installed
* Tue Jun  2 12:00:00 2020 Kamil Dudka <kdudka@redhat.com> - 7.29.0-59
- http: free protocol-specific struct in setup_connection callback (#1836773)

* Mon Mar 23 12:00:00 2020 Kamil Dudka <kdudka@redhat.com> - 7.29.0-58
- fix heap buffer overflow in function tftp_receive_packet() (CVE-2019-5482)

* Wed Nov 27 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-57
- allow curl to POST from a char device (#1769307)

* Tue Oct  1 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-56
- fix auth failure with duplicated WWW-Authenticate header (#1754736)

* Tue Aug  6 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-55
- fix TFTP receive buffer overflow (CVE-2019-5436)

* Mon Jun  3 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-54
- make ` + "`curl --tlsv1`" + ` backward compatible (#1672639)

* Mon May 27 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-53
- backport the --tls-max option of curl and TLS 1.3 ciphers (#1672639)

* Fri Mar  1 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-52
- prevent curl --rate-limit from hanging on file URLs (#1281969)
- fix NTLM password overflow via integer overflow (CVE-2018-14618)
- fix bad arithmetic when outputting warnings to stderr (CVE-2018-16842)
- backport options to force TLS 1.3 in curl and libcurl (#1672639)
- prevent curl --rate-limit from crashing on https URLs (#1683292)

* Wed Aug  8 12:00:00 2018 Kamil Dudka <kdudka@redhat.com> - 7.29.0-51
- require a new enough version of nss-pem to avoid regression in yum (#1610998)

* Thu Jun  7 12:00:00 2018 Kamil Dudka <kdudka@redhat.com> - 7.29.0-50
- remove dead code, detected by Coverity Analysis
- remove unused variable, detected by GCC and Clang

* Wed Jun  6 12:00:00 2018 Kamil Dudka <kdudka@redhat.com> - 7.29.0-49
- make curl --speed-limit work with TFTP (#1584750)

* Wed May 30 12:00:00 2018 Kamil Dudka <kdudka@redhat.com> - 7.29.0-48
- fix RTSP bad headers buffer over-read (CVE-2018-1000301)
- fix FTP path trickery leads to NIL byte out of bounds write (CVE-2018-1000120)
- fix LDAP NULL pointer dereference (CVE-2018-1000121)
- fix RTSP RTP buffer over-read (CVE-2018-1000122)
- http: prevent custom Authorization headers in redirects (CVE-2018-1000007)
- doc: --tlsauthtype works only if built with TLS-SRP support (#1542256)
- update certificates in the test-suite because they expire soon (#1572723)

* Fri Mar  2 12:00:00 2018 Kamil Dudka <kdudka@redhat.com> - 7.29.0-47
- make NSS deallocate PKCS #11 objects early enough (#1510247)

* Mon Dec 11 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> - 7.29.0-46
- reset authentication state when HTTP transfer is done (#1511523)

* Mon Oct 23 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> - 7.29.0-45
- fix buffer overflow while processing IMAP FETCH response (CVE-2017-1000257)

* Thu Sep 14 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-44
- drop 0109-curl-7.29.0-crl-valgrind.patch no longer needed (#1427883)

* Wed Sep 13 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-43
- curl --socks5-{basic,gssapi}: control socks5 auth (#1409208)
- nss: fix a memory leak when CURLOPT_CRLFILE is used (#1427883)
- nss: do not leak PKCS #11 slot while loading a key (#1444860)
- nss: fix a possible use-after-free in SelectClientCert() (#1473158)

* Wed Mar 29 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-42
- fix use of uninitialized variable detected by Covscan

* Wed Mar 29 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-41
- make FTPS work with --proxytunnel (#1420327)

* Mon Mar 27 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-40
- make FTPS work with --proxytunnel (#1420327)

* Wed Mar  1 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-39
- work around race condition in PK11_FindSlotByName() in NSS (#1404815)

* Thu Feb  9 12:00:00 2017 Kamil Dudka <kdudka@redhat.com> 7.29.0-38
- make FTPS work with --proxytunnel (#1420327)

* Thu Oct  6 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-37
- fix tight loop in non-blocking TLS handhsake over proxy (#1388162)
- handle cookies with numerical IPv6 address (#1341503)
- make libcurl recognize chacha20-poly1305 and SHA384 cipher-suites (#1374740)
- curl -E: allow to escape ':' in cert nickname (#1376062)
- run automake in %prep to avoid patching Makefile.in files from now on

* Tue Sep 20 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-36
- reject negative string lengths in curl_easy_[un]escape() (CVE-2016-7167)

* Fri Aug 26 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-35
- fix incorrect use of a previously loaded certificate from file
  (related to CVE-2016-5420)

* Wed Aug 17 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-34
- acknowledge the --no-sessionid/CURLOPT_SSL_SESSIONID_CACHE option
  (required by the fix for CVE-2016-5419)

* Thu Aug 11 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-33
- fix re-using connections with wrong client cert (CVE-2016-5420)
- fix TLS session resumption client cert bypass (CVE-2016-5419)

* Mon Jun 20 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-32
- configure: improve detection of GCC's -fvisibility= flag

* Mon Jun 20 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-31
- prevent curl_multi_wait() from missing an event (#1347904)

* Tue Feb 16 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-30
- curl.1: --disable-{eprt,epsv} are ignored for IPv6 hosts (#1305974)

* Fri Jan 15 12:00:00 2016 Kamil Dudka <kdudka@redhat.com> 7.29.0-29
- SSH: make CURLOPT_SSH_PUBLIC_KEYFILE treat "" as NULL (#1275769)

* Mon Nov  2 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-28
- prevent NSS from incorrectly re-using a session (#1269855)
- call PR_Cleanup() in the upstream test-suite if NSPR is used (#1243324)
- disable unreliable upstream test-case 2032 (#1241168)

* Tue Oct 27 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-27
- SSH: do not require public key file for user authentication (#1275769)

* Tue Sep  8 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-26
- implement 'curl --unix-socket' and CURLOPT_UNIX_SOCKET_PATH (#1263318)
- improve parsing of URL-encoded user name and password (#1260178)
- prevent test46 from failing due to expired cookie (#1258834)

* Mon May 11 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-25
- fix spurious failure of test 1500 on ppc64le (#1218272)

* Tue May  5 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-24
- use the default min/max TLS version provided by NSS (#1170339)
- improve handling of timeouts and blocking direction to speed up FTP (#1218272)

* Mon Apr 27 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-23
- require credentials to match for NTLM re-use (CVE-2015-3143)
- close Negotiate connections when done (CVE-2015-3148)

* Thu Jan  8 12:00:00 2015 Kamil Dudka <kdudka@redhat.com> 7.29.0-22
- reject CRLFs in URLs passed to proxy (CVE-2014-8150)

* Thu Dec 18 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-21
- use only full matches for hosts used as IP address in cookies (CVE-2014-3613)
- fix handling of CURLOPT_COPYPOSTFIELDS in curl_easy_duphandle (CVE-2014-3707)

* Thu Nov 27 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-20
- eliminate unnecessary delay when resolving host from /etc/hosts (#1130239)
- allow to enable/disable new AES cipher-suites (#1066065)
- call PR_Cleanup() on curl tool exit if NSPR is used (#1071254)
- implement non-blocking TLS handshake (#1091429)
- fix limited connection re-use for unencrypted HTTP (#1101092)
- disable libcurl-level downgrade to SSLv3 (#1154060)
- include response headers added by proxy in CURLINFO_HEADER_SIZE (#1161182)
- ignore CURLOPT_FORBID_REUSE during NTLM HTTP auth (#1166264)

* Wed Mar 26 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-19
- fix connection re-use when using different log-in credentials (CVE-2014-0138)

* Mon Mar 17 12:00:00 2014 Paul Howarth <paul@city-fan.org> 7.29.0-18
- add all perl build requirements for the test suite, in a portable way

* Tue Feb 18 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-17
- fix documentation of curl's options --tlsv1.[0-2] (#1066364)

* Tue Feb 11 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-16
- allow to use TLS > 1.0 if built against recent NSS (#1036789)
- use proxy name in error message when proxy is used (#1042831)
- refresh expired cookie in test172 from upstream test-suite (#1063693)

* Fri Jan 31 12:00:00 2014 Kamil Dudka <kdudka@redhat.com> 7.29.0-15
- allow to use ECC ciphers if NSS implements them (#1058776)
- re-use of wrong HTTP NTLM connection in libcurl (CVE-2014-0015)

* Fri Jan 24 12:00:00 2014 Daniel Mach <dmach@redhat.com> - 7.29.0-14
- Mass rebuild 2014-01-24

* Fri Dec 27 12:00:00 2013 Daniel Mach <dmach@redhat.com> - 7.29.0-13
- Mass rebuild 2013-12-27

* Fri Oct 11 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-12
- do not limit the speed of SCP upload on a fast connection (#1014928)

* Mon Sep  9 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-11
- avoid delay if FTP is aborted in CURLOPT_HEADERFUNCTION callback (#1005686)

* Wed Sep  4 12:00:00 2013 Kamil Dudka <kdudka@redaht.com> 7.29.0-10
- avoid a busy-loop in curl_easy_perform()

* Fri Aug 30 12:00:00 2013 Kamil Dudka <kdudka@redaht.com> 7.29.0-9
- FTP: when EPSV gets a 229 but fails to connect, retry with PASV (#1002815)

* Tue Jul  9 12:00:00 2013 Kamil Dudka <kdudka@redaht.com> 7.29.0-8
- mention all option listed in 'curl --help' in curl.1 man page

* Sat Jun 22 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-7
- fix heap-based buffer overflow in curl_easy_unescape() (CVE-2013-2174)

* Fri Apr 26 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-6
- prevent an artificial timeout event due to stale speed-check data (#906031)
- show proper host name on failed resolve (#957173)

* Fri Apr 12 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-5
- fix cookie tailmatching to prevent cross-domain leakage (CVE-2013-1944)

* Tue Mar 12 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-4
- do not ignore poll() failures other than EINTR (#919127)
- curl_global_init() now accepts the CURL_GLOBAL_ACK_EINTR flag (#919127)

* Wed Mar  6 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-3
- switch SSL socket into non-blocking mode after handshake (#960765)
- drop the hide_selinux.c hack no longer needed in %check

* Fri Feb 22 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-2
- fix a SIGSEGV when closing an unused multi handle (#914411)

* Wed Feb  6 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.29.0-1
- new upstream release (fixes CVE-2013-0249)

* Tue Jan 15 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.28.1-3
- require valgrind for build only on i386 and x86_64 (#886891)

* Tue Jan 15 12:00:00 2013 Kamil Dudka <kdudka@redhat.com> 7.28.1-2
- prevent NSS from crashing on client auth hook failure
- clear session cache if a client cert from file is used
- fix error messages for CURLE_SSL_{CACERT,CRL}_BADFILE

* Tue Nov 20 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.28.1-1
- new upstream release

* Wed Oct 31 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.28.0-1
- new upstream release

* Mon Oct  1 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.27.0-3
- use the upstream facility to disable problematic tests
- do not crash if MD5 fingerprint is not provided by libssh2

* Wed Aug  1 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.27.0-2
- eliminate unnecessary inotify events on upload via file protocol (#844385)

* Sat Jul 28 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.27.0-1
- new upstream release

* Mon Jul 23 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.26.0-6
- print reason phrase from HTTP status line on error (#676596)

* Wed Jul 18 12:00:00 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.26.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Sat Jun  9 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.26.0-4
- fix duplicated SSL handshake with multi interface and proxy (#788526)

* Wed May 30 12:00:00 2012 Karsten Hopp <karsten@redhat.com> 7.26.0-3
- disable test 1319 on ppc64, server times out

* Mon May 28 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.26.0-2
- use human-readable error messages provided by NSS (upstream commit 72f4b534)

* Fri May 25 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.26.0-1
- new upstream release

* Wed Apr 25 12:00:00 2012 Karsten Hopp <karsten@redhat.com> 7.25.0-3
- valgrind on ppc64 works fine, disable ppc32 only

* Wed Apr 25 12:00:00 2012 Karsten Hopp <karsten@redhat.com> 7.25.0-3
- drop BR valgrind on PPC(64) until bugzilla #810992 gets fixed

* Fri Apr 13 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.25.0-2
- use NSS_InitContext() to initialize NSS if available (#738456)
- provide human-readable names for NSS errors (upstream commit a60edcc6)

* Fri Mar 23 12:00:00 2012 Paul Howarth <paul@city-fan.org> 7.25.0-1
- new upstream release (#806264)
- fix character encoding of docs with a patch rather than just iconv
- update debug and multilib patches
- don't use macros for commands
- reduce size of %prep output for readability

* Tue Jan 24 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.24.0-1
- new upstream release (fixes CVE-2012-0036)

* Thu Jan  5 12:00:00 2012 Paul Howarth <paul@city-fan.org> 7.23.0-6
- rebuild for gcc 4.7

* Mon Jan  2 12:00:00 2012 Kamil Dudka <kdudka@redhat.com> 7.23.0-5
- upstream patch that allows to run FTPS tests with nss-3.13 (#760060)

* Tue Dec 27 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.23.0-4
- allow to run FTPS tests with nss-3.13 (#760060)

* Sun Dec 25 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.23.0-3
- avoid unnecessary timeout event when waiting for 100-continue (#767490)

* Mon Nov 21 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.23.0-2
- curl -JO now uses -O name if no C-D header comes (upstream commit c532604)

* Wed Nov 16 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.23.0-1
- new upstream release (#754391)

* Mon Sep 19 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.22.0-2
- nss: select client certificates by DER (#733657)

* Tue Sep 13 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.22.0-1
- new upstream release
- curl-config now provides dummy --static-libs option (#733956)

* Sun Aug 21 12:00:00 2011 Paul Howarth <paul@city-fan.org> 7.21.7-4
- actually fix SIGSEGV of curl -O -J given more than one URL (#723075)

* Mon Aug 15 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.7-3
- fix SIGSEGV of curl -O -J given more than one URL (#723075)
- introduce the --delegation option of curl (#730444)
- initialize NSS with no database if the selected database is broken (#728562)

* Wed Aug  3 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.7-2
- add a new option CURLOPT_GSSAPI_DELEGATION (#719939)

* Thu Jun 23 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.7-1
- new upstream release (fixes CVE-2011-2192)

* Wed Jun  8 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.6-2
- avoid an invalid timeout event on a reused handle (#679709)

* Sat Apr 23 12:00:00 2011 Paul Howarth <paul@city-fan.org> 7.21.6-1
- new upstream release

* Mon Apr 18 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.5-2
- fix the output of curl-config --version (upstream commit 82ecc85)

* Mon Apr 18 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.5-1
- new upstream release

* Sat Apr 16 12:00:00 2011 Peter Robinson <pbrobinson@gmail.com> 7.21.4-4
- no valgrind on ARMv5 arches

* Sat Mar  5 12:00:00 2011 Dennis Gilmore <dennis@ausil.us> 7.21.4-3
- no valgrind on sparc arches

* Tue Feb 22 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.4-2
- do not ignore failure of SSL handshake (upstream commit 7aa2d10)

* Fri Feb 18 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.4-1
- new upstream release
- avoid memory leak on SSL connection failure (upstream commit a40f58d)
- work around valgrind bug (#678518)

* Tue Feb  8 12:00:00 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.21.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Jan 12 12:00:00 2011 Kamil Dudka <kdudka@redhat.com> 7.21.3-2
- build libcurl with --enable-hidden-symbols

* Thu Dec 16 12:00:00 2010 Paul Howarth <paul@city-fan.org> 7.21.3-1
- update to 7.21.3:
  - added --noconfigure switch to testcurl.pl
  - added --xattr option
  - added CURLOPT_RESOLVE and --resolve
  - added CURLAUTH_ONLY
  - added version-check.pl to the examples dir
  - check for libcurl features for some command line options
  - Curl_setopt: disallow CURLOPT_USE_SSL without SSL support
  - http_chunks: remove debug output
  - URL-parsing: consider ? a divider
  - SSH: avoid using the libssh2_ prefix
  - SSH: use libssh2_session_handshake() to work on win64
  - ftp: prevent server from hanging on closed data connection when stopping
    a transfer before the end of the full transfer (ranges)
  - LDAP: detect non-binary attributes properly
  - ftp: treat server's response 421 as CURLE_OPERATION_TIMEDOUT
  - gnutls->handshake: improved timeout handling
  - security: pass the right parameter to init
  - krb5: use GSS_ERROR to check for error
  - TFTP: resend the correct data
  - configure: fix autoconf 2.68 warning: no AC_LANG_SOURCE call detected
  - GnuTLS: now detects socket errors on Windows
  - symbols-in-versions: updated en masse
  - added a couple of examples that were missing from the tarball
  - Curl_send/recv_plain: return errno on failure
  - Curl_wait_for_resolv (for c-ares): correct timeout
  - ossl_connect_common: detect connection re-use
  - configure: prevent link errors with --librtmp
  - openldap: use remote port in URL passed to ldap_init_fd()
  - url: provide dead_connection flag in Curl_handler::disconnect
  - lots of compiler warning fixes
  - ssh: fix a download resume point calculation
  - fix getinfo CURLINFO_LOCAL* for reused connections
  - multi: the returned running handles counter could turn negative
  - multi: only ever consider pipelining for connections doing HTTP(S)
- drop upstream patches now in tarball
- update bz650255 and disable-test1112 patches to apply against new codebase
- add workaround for false-positive glibc-detected buffer overflow in tftpd
  test server with FORTIFY_SOURCE (similar to #515361)

* Fri Nov 12 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.2-5
- do not send QUIT to a dead FTP control connection (#650255)
- pull back glibc's implementation of str[n]casecmp(), #626470 appears fixed

* Tue Nov  9 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.2-4
- prevent FTP client from hanging on unrecognized ABOR response (#649347)
- return more appropriate error code in case FTP server session idle
  timeout has exceeded (#650255)

* Fri Oct 29 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.2-3
- prevent FTP server from hanging on closed data connection (#643656)

* Thu Oct 14 12:00:00 2010 Paul Howarth <paul@city-fan.org> 7.21.2-2
- enforce versioned libssh2 dependency for libcurl (#642796)

* Wed Oct 13 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.2-1
- new upstream release, drop applied patches
- make 0102-curl-7.21.2-debug.patch less intrusive

* Wed Sep 29 12:00:00 2010 jkeating - 7.21.1-6
- Rebuilt for gcc bug 634757

* Sat Sep 11 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.1-5
- make it possible to run SCP/SFTP tests on x86_64 (#632914)

* Tue Sep  7 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.1-4
- work around glibc/valgrind problem on x86_64 (#631449)

* Tue Aug 24 12:00:00 2010 Paul Howarth <paul@city-fan.org> 7.21.1-3
- fix up patches so there's no need to run autotools in the rpm build
- drop buildreq automake
- drop dependency on automake for devel package from F-14, where
  %{_datadir}/aclocal is included in the filesystem package
- drop dependency on pkgconfig for devel package from F-11, where
  pkgconfig dependencies are auto-generated

* Mon Aug 23 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.1-2
- re-enable test575 on s390(x), already fixed (upstream commit d63bdba)
- modify system headers to work around gcc bug (#617757)
- curl -T now ignores file size of special files (#622520)
- fix kerberos proxy authentication for https (#625676)
- work around glibc/valgrind problem on x86_64 (#626470)

* Thu Aug 12 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.1-1
- new upstream release

* Mon Jul 12 12:00:00 2010 Dan Hor?k <dan[at]danny.cz> 7.21.0-3
- disable test 575 on s390(x)

* Mon Jun 28 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.0-2
- add support for NTLM authentication (#603783)

* Wed Jun 16 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.21.0-1
- new upstream release, drop applied patches
- update of %description
- disable valgrind for certain test-cases (libssh2 problem)

* Tue May 25 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.1-6
- fix -J/--remote-header-name to strip CR-LF (upstream patch)

* Wed Apr 28 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.1-5
- CRL support now works again (#581926)
- make it possible to start a testing OpenSSH server when building with SELinux
  in the enforcing mode (#521087)

* Sat Apr 24 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.1-4
- upstream patch preventing failure of test536 with threaded DNS resolver
- upstream patch preventing SSL handshake timeout underflow

* Thu Apr 22 12:00:00 2010 Paul Howarth <paul@city-fan.org> 7.20.1-3
- replace Rawhide s390-sleep patch with a more targeted patch adding a
  delay after tests 513 and 514 rather than after all tests

* Wed Apr 21 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.1-2
- experimentally enabled threaded DNS lookup
- make curl-config multilib ready again (#584107)

* Mon Apr 19 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.1-1
- new upstream release

* Tue Mar 23 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.0-4
- add missing quote in libcurl.m4 (#576252)

* Fri Mar 19 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.0-3
- throw CURLE_SSL_CERTPROBLEM in case peer rejects a certificate (#565972)
- valgrind temporarily disabled (#574889)
- kerberos installation prefix has been changed

* Wed Feb 24 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.0-2
- exclude test1112 from the test suite (#565305)

* Thu Feb 11 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.20.0-1
- new upstream release - added support for IMAP(S), POP3(S), SMTP(S) and RTSP
- dropped patches applied upstream
- dropped curl-7.16.0-privlibs.patch no longer useful
- a new patch forcing -lrt when linking the curl tool and test-cases

* Fri Jan 29 12:00:00 2010 Kamil Dudka <kdudka@redhat.com> 7.19.7-11
- upstream patch adding a new option -J/--remote-header-name
- dropped temporary workaround for #545779

* Thu Jan 14 12:00:00 2010 Chris Weyl <cweyl@alumni.drew.edu> 7.19.7-10
- bump for libssh2 rebuild

* Sun Dec 20 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-9
- temporary workaround for #548269
  (restored behavior of 7.19.7-4)

* Wed Dec  9 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-8
- replace hard wired port numbers in the test suite

* Wed Dec  9 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-7
- use different port numbers for 32bit and 64bit builds
- temporary workaround for #545779

* Tue Dec  8 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-6
- make it possible to run test241
- re-enable SCP/SFTP tests (#539444)

* Sat Dec  5 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-5
- avoid use of uninitialized value in lib/nss.c
- suppress failure of test513 on s390

* Tue Dec  1 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-4
- do not require valgrind on s390 and s390x
- temporarily disabled SCP/SFTP test-suite (#539444)

* Thu Nov 12 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-3
- fix crash on doubly closed NSPR descriptor, patch contributed
  by Kevin Baughman (#534176)
- new version of patch for broken TLS servers (#525496, #527771)

* Wed Nov  4 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-2
- increased release number (CVS problem)

* Wed Nov  4 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.7-1
- new upstream release, dropped applied patches
- workaround for broken TLS servers (#525496, #527771)

* Wed Oct 14 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-13
- fix timeout issues and gcc warnings within lib/nss.c

* Tue Oct  6 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-12
- upstream patch for NSS support written by Guenter Knauf

* Wed Sep 30 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-11
- build libcurl with c-ares support (#514771)

* Sun Sep 27 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-10
- require libssh2>=1.2 properly (#525002)

* Sat Sep 26 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-9
- let curl test-suite use valgrind
- require libssh2>=1.2 (#525002)

* Mon Sep 21 12:00:00 2009 Chris Weyl <cweyl@alumni.drew.edu> - 7.19.6-8
- rebuild for libssh2 1.2

* Thu Sep 17 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-7
- make curl test-suite more verbose

* Wed Sep 16 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-6
- update polling patch to the latest upstream version

* Thu Sep  3 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-5
- cover ssh and stunnel support by the test-suite

* Wed Sep  2 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-4
- use pkg-config to find nss and libssh2 if possible
- better patch (not only) for SCP/SFTP polling
- improve error message for not matching common name (#516056)

* Fri Aug 21 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-3
- avoid tight loop during a sftp upload
- http://permalink.gmane.org/gmane.comp.web.curl.library/24744

* Tue Aug 18 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-2
- let curl package depend on the same version of libcurl

* Fri Aug 14 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.6-1
- new upstream release, dropped applied patches
- changed NSS code to not ignore the value of ssl.verifyhost and produce more
  verbose error messages (#516056)

* Wed Aug 12 12:00:00 2009 Ville Skytt? <ville.skytta@iki.fi> - 7.19.5-10
- Use lzma compressed upstream tarball.

* Fri Jul 24 12:00:00 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.19.5-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed Jul 22 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-8
- do not pre-login to all PKCS11 slots, it causes problems with HW tokens
- try to select client certificate automatically when not specified, thanks
  to Claes Jakobsson

* Fri Jul 10 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-7
- fix SIGSEGV when using NSS client certificates, thanks to Claes Jakobsson

* Sun Jul  5 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-6
- force test suite to use the just built libcurl, thanks to Paul Howarth

* Thu Jul  2 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-5
- run test suite after build
- enable built-in manual

* Wed Jun 24 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-4
- fix bug introduced by the last build (#504857)

* Wed Jun 24 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-3
- exclude curlbuild.h content from spec (#504857)

* Wed Jun 10 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-2
- avoid unguarded comparison in the spec file, thanks to R P Herrold (#504857)

* Tue May 19 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.5-1
- update to 7.19.5, dropped applied patches

* Mon May 11 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-11
- fix infinite loop while loading a private key, thanks to Michael Cronenworth
  (#453612)

* Mon Apr 27 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-10
- fix curl/nss memory leaks while using client certificate (#453612, accepted
  by upstream)

* Wed Apr 22 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-9
- add missing BuildRequire for autoconf

* Wed Apr 22 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-8
- fix configure.ac to not discard -g in CFLAGS (#496778)

* Tue Apr 21 12:00:00 2009 Debarshi Ray <rishi@fedoraproject.org> 7.19.4-7
- Fixed configure to respect the environment's CFLAGS and CPPFLAGS settings.

* Tue Apr 14 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-6
- upstream patch fixing memory leak in lib/nss.c (#453612)
- remove redundant dependency of libcurl-devel on libssh2-devel

* Wed Mar 18 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-5
- enable 6 additional crypto algorithms by default (#436781,
  accepted by upstream)

* Thu Mar 12 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-4
- fix memory leak in src/main.c (accepted by upstream)
- avoid using %ifarch

* Wed Mar 11 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.4-3
- make libcurl-devel multilib-ready (bug #488922)

* Fri Mar  6 12:00:00 2009 Jindrich Novy <jnovy@redhat.com> 7.19.4-2
- drop .easy-leak patch, causes problems in pycurl (#488791)
- fix libcurl-devel dependencies (#488895)

* Tue Mar  3 12:00:00 2009 Jindrich Novy <jnovy@redhat.com> 7.19.4-1
- update to 7.19.4 (fixes CVE-2009-0037)
- fix leak in curl_easy* functions, thanks to Kamil Dudka
- drop nss-fix patch, applied upstream

* Tue Feb 24 12:00:00 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 7.19.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Tue Feb 17 12:00:00 2009 Kamil Dudka <kdudka@redhat.com> 7.19.3-1
- update to 7.19.3, dropped applied nss patches
- add patch fixing 7.19.3 curl/nss bugs

* Mon Dec 15 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-9
- rebuild for f10/rawhide cvs tag clashes

* Sat Dec  6 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-8
- use improved NSS patch, thanks to Rob Crittenden (#472489)

* Tue Sep  9 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-7
- update the thread safety patch, thanks to Rob Crittenden (#462217)

* Wed Sep  3 12:00:00 2008 Warren Togami <wtogami@redhat.com> 7.18.2-6
- add thread safety to libcurl NSS cleanup() functions (#459297)

* Fri Aug 22 12:00:00 2008 Tom "spot" Callaway <tcallawa@redhat.com> 7.18.2-5
- undo mini libcurl.so.3

* Mon Aug 11 12:00:00 2008 Tom "spot" Callaway <tcallawa@redhat.com> 7.18.2-4
- make miniature library for libcurl.so.3

* Fri Jul  4 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-3
- enable support for libssh2 (#453958)

* Wed Jun 18 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-2
- fix curl_multi_perform() over a proxy (#450140), thanks to
  Rob Crittenden

* Wed Jun  4 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.2-1
- update to 7.18.2

* Wed May  7 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.1-2
- spec cleanup, thanks to Paul Howarth (#225671)
  - drop BR: libtool
  - convert CHANGES and README to UTF-8
  - _GNU_SOURCE in CFLAGS is no more needed
  - remove bogus rpath

* Mon Mar 31 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.1-1
- update to curl 7.18.1 (fixes #397911)
- add ABI docs for libcurl
- remove --static-libs from curl-config
- drop curl-config patch, obsoleted by @SSL_ENABLED@ autoconf
  substitution (#432667)

* Fri Feb 15 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.0-2
- define _GNU_SOURCE so that NI_MAXHOST gets defined from glibc

* Mon Jan 28 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.18.0-1
- update to curl-7.18.0
- drop sslgen patch -> applied upstream
- fix typo in description

* Tue Jan 22 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.17.1-6
- fix curl-devel obsoletes so that we don't break F8->F9 upgrade
  path (#429612)

* Tue Jan  8 12:00:00 2008 Jindrich Novy <jnovy@redhat.com> 7.17.1-5
- do not attempt to close a bad socket (#427966),
  thanks to Caolan McNamara

* Tue Dec  4 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.17.1-4
- rebuild because of the openldap soname bump
- remove old nsspem patch

* Fri Nov 30 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.17.1-3
- drop useless ldap library detection since curl doesn't
  dlopen()s it but links to it -> BR: openldap-devel
- enable LDAPS support (#225671), thanks to Paul Howarth
- BR: krb5-devel to reenable GSSAPI support
- simplify build process
- update description

* Wed Nov 21 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.17.1-2
- update description to contain complete supported servers list (#393861)

* Sat Nov 17 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.17.1-1
- update to curl 7.17.1
- include patch to enable SSL usage in NSS when a socket is opened
  nonblocking, thanks to Rob Crittenden (rcritten@redhat.com)

* Wed Oct 24 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-10
- correctly provide/obsolete curl-devel (#130251)

* Wed Oct 24 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-9
- create libcurl and libcurl-devel subpackages (#130251)

* Thu Oct 11 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-8
- list features correctly when curl is compiled against NSS (#316191)

* Mon Sep 17 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-7
- add zlib-devel BR to enable gzip compressed transfers in curl (#292211)

* Mon Sep 10 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-6
- provide webclient (#225671)

* Thu Sep  6 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-5
- add support for the NSS PKCS#11 pem reader so the command-line is the
  same for both OpenSSL and NSS by Rob Crittenden (rcritten@redhat.com)
- switch to NSS again

* Mon Sep  3 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-4
- revert back to use OpenSSL (#266021)

* Mon Aug 27 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-3
- don't use openssl, use nss instead

* Fri Aug 10 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-2
- fix anonymous ftp login (#251570), thanks to David Cantrell

* Wed Jul 11 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.4-1
- update to 7.16.4

* Mon Jun 25 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.3-1
- update to 7.16.3
- drop .print patch, applied upstream
- next series of merge review fixes by Paul Howarth
- remove aclocal stuff, no more needed
- simplify makefile arguments
- don't reference standard library paths in libcurl.pc
- include docs/CONTRIBUTE

* Mon Jun 18 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.2-5
- don't print like crazy (#236981), backported from upstream CVS

* Fri Jun 15 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.2-4
- another series of review fixes (#225671),
  thanks to Paul Howarth
- check version of ldap library automatically
- don't use %makeinstall and preserve timestamps
- drop useless patches

* Fri May 11 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.2-3
- add automake BR to curl-devel to fix aclocal dir. ownership,
  thanks to Patrice Dumas

* Thu May 10 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.2-2
- package libcurl.m4 in curl-devel (#239664), thanks to Quy Tonthat

* Wed Apr 11 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.2-1
- update to 7.16.2

* Mon Feb 19 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.1-3
- don't create/ship static libraries (#225671)

* Mon Feb  5 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.1-2
- merge review related spec fixes (#225671)

* Mon Jan 29 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.1-1
- update to 7.16.1

* Tue Jan 16 12:00:00 2007 Jindrich Novy <jnovy@redhat.com> 7.16.0-5
- don't package generated makefiles for docs/examples to avoid
  multilib conflicts

* Mon Dec 18 12:00:00 2006 Jindrich Novy <jnovy@redhat.com> 7.16.0-4
- convert spec to UTF-8
- don't delete BuildRoot in %prep phase
- rpmlint fixes

* Thu Nov 16 12:00:00 2006 Jindrich Novy <jnovy@redhat.com> -7.16.0-3
- prevent curl from dlopen()ing missing ldap libraries so that
  ldap:// requests work (#215928)

* Tue Oct 31 12:00:00 2006 Jindrich Novy <jnovy@redhat.com> - 7.16.0-2
- fix BuildRoot
- add Requires: pkgconfig for curl-devel
- move LDFLAGS and LIBS to Libs.private in libcurl.pc.in (#213278)

* Mon Oct 30 12:00:00 2006 Jindrich Novy <jnovy@redhat.com> - 7.16.0-1
- update to curl-7.16.0

* Thu Aug 24 12:00:00 2006 Jindrich Novy <jnovy@redhat.com> - 7.15.5-1.fc6
- update to curl-7.15.5
- use %{?dist}

* Fri Jun 30 12:00:00 2006 Ivana Varekova <varekova@redhat.com> - 7.15.4-1
- update to 7.15.4

* Mon Mar 20 12:00:00 2006 Ivana Varekova <varekova@redhat.com> - 7.15.3-1
- fix multilib problem using pkg-config
- update to 7.15.3

* Thu Feb 23 12:00:00 2006 Ivana Varekova <varekova@redhat.com> - 7.15.1-2
- fix multilib problem - #181290 -
  curl-devel.i386 not installable together with curl-devel.x86-64

* Fri Feb 10 12:00:00 2006 Jesse Keating <jkeating@redhat.com> - 7.15.1-1.2.1
- bump again for double-long bug on ppc(64)

* Tue Feb  7 12:00:00 2006 Jesse Keating <jkeating@redhat.com> - 7.15.1-1.2
- rebuilt for new gcc4.1 snapshot and glibc changes

* Fri Dec  9 12:00:00 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Thu Dec  8 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.15.1-1
- update to 7.15.1 (bug 175191)

* Wed Nov 30 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.15.0-3
- fix curl-config bug 174556 - missing vernum value

* Wed Nov  9 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.15.0-2
- rebuilt

* Tue Oct 18 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.15.0-1
- update to 7.15.0

* Thu Oct 13 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.14.1-1
- update to 7.14.1

* Thu Jun 16 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.14.0-1
- rebuild new version

* Tue May  3 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.13.1-3
- fix bug 150768 - curl-7.12.3-2 breaks basic authentication
  used Daniel Stenberg patch

* Mon Apr 25 12:00:00 2005 Joe Orton <jorton@redhat.com> 7.13.1-2
- update to use ca-bundle in /etc/pki
- mark License as MIT not MPL

* Wed Mar  9 12:00:00 2005 Ivana Varekova <varekova@redhat.com> 7.13.1-1
- rebuilt (7.13.1)

* Tue Mar  1 12:00:00 2005 Tomas Mraz <tmraz@redhat.com> 7.13.0-2
- rebuild with openssl-0.9.7e

* Sun Feb 13 12:00:00 2005 Florian La Roche <laroche@redhat.com>
- 7.13.0

* Wed Feb  9 12:00:00 2005 Joe Orton <jorton@redhat.com> 7.12.3-3
- don't pass /usr to --with-libidn to remove "-L/usr/lib" from
  'curl-config --libs' output on x86_64.

* Fri Jan 28 12:00:00 2005 Adrian Havill <havill@redhat.com> 7.12.3-1
- Upgrade to 7.12.3, which uses poll() for FDSETSIZE limit (#134794)
- require libidn-devel for devel subpkg (#141341)
- remove proftpd kludge; included upstream

* Wed Oct  6 12:00:00 2004 Adrian Havill <havill@redhat.com> 7.12.1-1
- upgrade to 7.12.1
- enable GSSAPI auth (#129353)
- enable I18N domain names (#134595)
- workaround for broken ProFTPD SSL auth (#134133). Thanks to
  Aleksandar Milivojevic

* Wed Sep 29 12:00:00 2004 Adrian Havill <havill@redhat.com> 7.12.0-4
- move new docs position so defattr gets applied

* Mon Sep 27 12:00:00 2004 Warren Togami <wtogami@redhat.com> 7.12.0-3
- remove INSTALL, move libcurl docs to -devel

* Mon Jul 26 12:00:00 2004 Jindrich Novy <jnovy@redhat.com>
- updated to 7.12.0
- updated nousr patch

* Tue Jun 15 12:00:00 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed Apr  7 12:00:00 2004 Adrian Havill <havill@redhat.com> 7.11.1-1
- upgraded; updated nousr patch
- added COPYING (#115956)
-

* Tue Mar  2 12:00:00 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Feb 13 12:00:00 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sat Jan 31 12:00:00 2004 Florian La Roche <Florian.LaRoche@redhat.de>
- update to 7.10.8
- remove patch2, already upstream

* Wed Oct 15 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-7
- aclocal before libtoolize
- move OpenLDAP license so it's present as a doc file, present in
  both the source and binary as per conditions

* Mon Oct 13 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-6
- add OpenLDAP copyright notice for usage of code, add OpenLDAP
  license for this code

* Tue Oct  7 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-5
- match serverAltName certs with SSL (#106168)

* Tue Sep 16 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-4.1
- bump n-v-r for RHEL

* Tue Sep 16 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-4
- restore ca cert bundle (#104400)
- require openssl, we want to use its ca-cert bundle

* Sun Sep  7 12:00:00 2003 Joe Orton <jorton@redhat.com> 7.10.6-3
- rebuild

* Fri Sep  5 12:00:00 2003 Joe Orton <jorton@redhat.com> 7.10.6-2.2
- fix to include libcurl.so

* Mon Aug 25 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-2.1
- bump n-v-r for RHEL

* Mon Aug 25 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-2
- devel subpkg needs openssl-devel as a Require (#102963)

* Mon Jul 28 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.6-1
- bumped version

* Tue Jul  1 12:00:00 2003 Adrian Havill <havill@redhat.com> 7.10.5-1
- bumped version

* Wed Jun  4 12:00:00 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sat Apr 12 12:00:00 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- update to 7.10.4
- adapt nousr patch

* Wed Jan 22 12:00:00 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Tue Jan 21 12:00:00 2003 Joe Orton <jorton@redhat.com> 7.9.8-4
- don't add -L/usr/lib to 'curl-config --libs' output

* Tue Jan  7 12:00:00 2003 Nalin Dahyabhai <nalin@redhat.com> 7.9.8-3
- rebuild

* Wed Nov  6 12:00:00 2002 Joe Orton <jorton@redhat.com> 7.9.8-2
- fix ` + "`curl-config --libs`" + ` output for libdir!=/usr/lib
- remove docs/LIBCURL from docs list; remove unpackaged libcurl.la
- libtoolize and reconf

* Mon Jul 22 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.8-1
- 7.9.8 (# 69473)

* Fri Jun 21 12:00:00 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Sun May 26 12:00:00 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu May 16 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.7-1
- 7.9.7

* Wed Apr 24 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.6-1
- 7.9.6

* Thu Mar 21 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.5-2
- Stop the curl-config script from printing -I/usr/include
  and -L/usr/lib (#59497)

* Fri Mar  8 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.5-1
- 7.9.5

* Tue Feb 26 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.3-2
- Rebuild

* Wed Jan 23 12:00:00 2002 Nalin Dahyabhai <nalin@redhat.com> 7.9.3-1
- update to 7.9.3

* Wed Jan  9 12:00:00 2002 Tim Powers <timp@redhat.com> 7.9.2-2
- automated rebuild

* Wed Jan  9 12:00:00 2002 Trond Eivind Glomsr?d <teg@redhat.com> 7.9.2-1
- 7.9.2

* Fri Aug 17 12:00:00 2001 Nalin Dahyabhai <nalin@redhat.com>
- include curl-config in curl-devel
- update to 7.8 to fix memory leak and strlcat() symbol pollution from libcurl

* Wed Jul 18 12:00:00 2001 Crutcher Dunnavant <crutcher@redhat.com>
- added openssl-devel build req

* Mon May 21 12:00:00 2001 Tim Powers <timp@redhat.com>
- built for the distro

* Tue Apr 24 12:00:00 2001 Jeff Johnson <jbj@redhat.com>
- upgrade to curl-7.7.2.
- enable IPv6.

* Fri Mar  2 12:00:00 2001 Tim Powers <timp@redhat.com>
- rebuilt against openssl-0.9.6-1

* Thu Jan  4 12:00:00 2001 Tim Powers <timp@redhat.com>
- fixed mising ldconfigs
- updated to 7.5.2, bug fixes

* Mon Dec 11 12:00:00 2000 Tim Powers <timp@redhat.com>
- updated to 7.5.1

* Mon Nov  6 12:00:00 2000 Tim Powers <timp@redhat.com>
- update to 7.4.1 to fix bug #20337, problems with curl -c
- not using patch anymore, it's included in the new source. Keeping
  for reference

* Fri Oct 20 12:00:00 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix bogus req in -devel package

* Fri Oct 20 12:00:00 2000 Tim Powers <timp@redhat.com>
- devel package needed defattr so that root owns the files

* Mon Oct 16 12:00:00 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to 7.3
- apply vsprintf/vsnprintf patch from Colin Phipps via Debian

* Mon Aug 21 12:00:00 2000 Nalin Dahyabhai <nalin@redhat.com>
- enable SSL support
- fix packager tag
- move buildroot to %{_tmppath}

* Tue Aug  1 12:00:00 2000 Tim Powers <timp@redhat.com>
- fixed vendor tag for bug #15028

* Mon Jul 24 12:00:00 2000 Prospector <prospector@redhat.com>
- rebuilt

* Tue Jul 11 12:00:00 2000 Tim Powers <timp@redhat.com>
- workaround alpha build problems with optimizations

* Mon Jul 10 12:00:00 2000 Tim Powers <timp@redhat.com>
- rebuilt

* Mon Jun  5 12:00:00 2000 Tim Powers <timp@redhat.com>
- put man pages in correct place
- use %makeinstall

* Mon Apr 24 12:00:00 2000 Tim Powers <timp@redhat.com>
- updated to 6.5.2

* Wed Nov  3 12:00:00 1999 Tim Powers <timp@redhat.com>
- updated sources to 6.2
- gzip man page

* Mon Aug 30 12:00:00 1999 Tim Powers <timp@redhat.com>
- changed group

* Thu Aug 26 12:00:00 1999 Tim Powers <timp@redhat.com>
- changelog started
- general cleanups, changed prefix to /usr, added manpage to files section
- including in Powertools

updates/7/x86_64/other_db                                                                                          | 1.5 MB  00:00:00

==================== Available Packages ====================
curl-7.29.0-59.el7_9.2.x86_64            updates
* Tue Nov  7 12:00:00 2023 Jacek Migacz <jmigacz@redhat.com> - 7.29.0-59.el7_9.2
- fix HTTP proxy deny use after free (CVE-2022-43552)
- rebuild certs with 2048-bit RSA keys

* Tue Jul 28 12:00:00 2020 Kamil Dudka <kdudka@redhat.com> - 7.29.0-59.el7_9.1
- avoid overwriting a local file with -J (CVE-2020-8177)

* Tue Jun  2 12:00:00 2020 Kamil Dudka <kdudka@redhat.com> - 7.29.0-59
- http: free protocol-specific struct in setup_connection callback (#1836773)

* Mon Mar 23 12:00:00 2020 Kamil Dudka <kdudka@redhat.com> - 7.29.0-58
- fix heap buffer overflow in function tftp_receive_packet() (CVE-2019-5482)

* Wed Nov 27 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-57
- allow curl to POST from a char device (#1769307)

* Tue Oct  1 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-56
- fix auth failure with duplicated WWW-Authenticate header (#1754736)

* Tue Aug  6 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-55
- fix TFTP receive buffer overflow (CVE-2019-5436)

* Mon Jun  3 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-54
- make ` + "`curl --tlsv1`" + ` backward compatible (#1672639)

* Mon May 27 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-53
- backport the --tls-max option of curl and TLS 1.3 ciphers (#1672639)

* Fri Mar  1 12:00:00 2019 Kamil Dudka <kdudka@redhat.com> - 7.29.0-52
- prevent curl --rate-limit from hanging on file URLs (#1281969)
- fix NTLM password overflow via integer overflow (CVE-2018-14618)
- fix bad arithmetic when outputting warnings to stderr (CVE-2018-16842)
- backport options to force TLS 1.3 in curl and libcurl (#1672639)
- prevent curl --rate-limit from crashing on https URLs (#1683292)

changelog stats. 2 pkgs, 2 source pkgs, 302 changelogs`

var expectedRHELOutputForExtractCVENumberForGivenChangelog = []string{"CVE-2022-43552", "CVE-2020-8177", "CVE-2019-5482"}

var inputRHELForExtractSecurityUpdatesApps = `Updating Subscription Management repositories.
Last metadata expiration check: 0:10:32 ago on Thursday 21 March 2024 08:10:06 AM CET.

NetworkManager.x86_64                                                           1:1.40.16-13.el8_9                                                                      rhel-8-for-x86_64-baseos-rpms
NetworkManager-config-server.noarch                                             1:1.40.16-13.el8_9                                                                      rhel-8-for-x86_64-baseos-rpms
NetworkManager-wwan.x86_64                                                      1:1.40.16-13.el8_9                                                                      rhel-8-for-x86_64-baseos-rpms
bpftool.x86_64                                                                  4.18.0-513.18.1.el8_9                                                                   rhel-8-for-x86_64-baseos-rpms
buildah.x86_64                                                                  1:1.31.3-3.module+el8.9.0+21243+a586538b                                                rhel-8-for-x86_64-appstream-rpms
containernetworking-plugins.x86_64                                              1:1.3.0-8.module+el8.9.0+21243+a586538b                                                 rhel-8-for-x86_64-appstream-rpms`

var expectedRHELOutForExtractSecurityUpdateApps = []string{"NetworkManager", "NetworkManager-config-server", "NetworkManager-wwan", "bpftool", "buildah", "containernetworking-plugins"}

func TestExtractCVENumberForGivenChangelog(t *testing.T) {
	assert := require.New(t)
	extractor := newRhelExtactor()

	output := extractor.ExtractCVENumberForGivenChangelog(testRHELInputForExtractCVEFromChangeLog, "7.29.0-56")
	assert.Equal(expectedRHELOutputForExtractCVENumberForGivenChangelog, output)
}

func TestExtractSecurityUpdatesApps(t *testing.T) {
	assert := require.New(t)
	extractor := newRhelExtactor()

	outputs := extractor.ExtractAppWithSecurityUpdate(inputRHELForExtractSecurityUpdatesApps)
	assert.NotEmpty(outputs)
	assert.Equal(len(expectedRHELOutForExtractSecurityUpdateApps), len(outputs))

	for i, output := range outputs {
		assert.Equal(expectedRHELOutForExtractSecurityUpdateApps[i], output.Name)
	}
}
