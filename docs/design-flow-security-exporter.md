# Design Diagram 

```mermaid
flowchart TD
  A[cron runs] --> B[fetch packages which have security update]
  B-->C[Get changelog of a package via package manager]
  C-->D[find changes in changelog that are from newer versions than whats installed]
  D-->E[take CVE numbers present in difference]
  E-->G[Get CVE score for each CVE number]
  G-->F[Update metrics with CVE number and it's score]
  F-->C
```

## Reference Links:
- https://www.cyberciti.biz/faq/linux-find-package-includes-a-fixpatch-via-cve-number/
- https://www.cyberciti.biz/faq/rhel-centos-yum-check-update-security-plugin/
- https://www.cyberciti.biz/faq/linux-find-out-patch-can-cve-applied/
- https://copyprogramming.com/howto/how-can-i-tell-if-a-cve-has-been-fixed-in-ubuntu-s-repositories

### Notes:

- We currently plan is to support debian/ubuntu and RHEL systems.
- We will be using API's provided by NVD: https://nvd.nist.gov/developers/vulnerabilities.
- NVD API is rate limited, https://nvd.nist.gov/developers/start-here.
- Click on this https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0853 link to get sample output.
