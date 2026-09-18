package pkgscanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"security-exporter/config"
)

func TestScan_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error for server 500 response")
	}
}

func TestScan_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestScan_EmptyCves(t *testing.T) {
	mockResult := ScanResult{
		ServerName:  "test-host",
		Family:      "debian",
		Release:     "12",
		ScannedCves: map[string]VulnInfo{},
		Packages:    Packages{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{mockResult})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "bash\t5.2\n"}
	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ScannedCves) != 0 {
		t.Errorf("expected 0 CVEs, got %d", len(result.ScannedCves))
	}
}

func TestScan_MultiplePackagesAndCves(t *testing.T) {
	mockResult := ScanResult{
		ServerName: "prod-server",
		Family:     "redhat",
		Release:    "9",
		ScannedCves: map[string]VulnInfo{
			"CVE-2024-0001": {
				CveID: "CVE-2024-0001",
				CveContents: map[string][]CveContent{
					"nvd": {{CveID: "CVE-2024-0001", Cvss3Score: 9.8}},
				},
				AffectedPackages: []AffectedPackage{
					{Name: "openssl", NotFixedYet: false},
				},
			},
			"CVE-2024-0002": {
				CveID: "CVE-2024-0002",
				CveContents: map[string][]CveContent{
					"nvd": {{CveID: "CVE-2024-0002", Cvss3Score: 4.3}},
				},
				AffectedPackages: []AffectedPackage{
					{Name: "kernel", NotFixedYet: true},
				},
			},
		},
		Packages: Packages{
			"openssl": {Name: "openssl", Version: "3.0.7-1", NewVersion: "3.0.8-1"},
			"kernel":  {Name: "kernel", Version: "5.14.0-1", NewVersion: ""},
			"bash":    {Name: "bash", Version: "5.2.15-1", NewVersion: ""},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{mockResult})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family:  "redhat",
		release: "9",
		pkgs:    "openssl\t0:3.0.7-1.el9\nkernel\t0:5.14.0-1.el9\nbash\t0:5.2.15-1.el9\n",
	}

	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.ScannedCves) != 2 {
		t.Errorf("expected 2 CVEs, got %d", len(result.ScannedCves))
	}

	cve1, ok := result.ScannedCves["CVE-2024-0001"]
	if !ok {
		t.Fatal("expected CVE-2024-0001 in results")
	}
	if cve1.AffectedPackages[0].Name != "openssl" {
		t.Errorf("expected openssl affected, got %s", cve1.AffectedPackages[0].Name)
	}

	cve2, ok := result.ScannedCves["CVE-2024-0002"]
	if !ok {
		t.Fatal("expected CVE-2024-0002 in results")
	}
	if !cve2.AffectedPackages[0].NotFixedYet {
		t.Error("expected kernel CVE to be marked as not fixed yet")
	}

	if len(result.Packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(result.Packages))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(ctx, coll)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestScan_UnreachableServer(t *testing.T) {
	sc, err := New(config.VulsServer{URL: "http://127.0.0.1:1"}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func generateTestCert(t *testing.T) (certPEM string, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEMBytes), string(keyPEMBytes)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file.pem")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
