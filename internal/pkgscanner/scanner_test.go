package pkgscanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"security-exporter/config"
)

type mockCollector struct {
	family  string
	release string
	pkgs    string
	srcPkgs string
	updates map[string]string
	err     error
}

func (m *mockCollector) CollectPackages(_ context.Context) (string, string, error) {
	if m.err != nil {
		return "", "", m.err
	}
	return m.pkgs, m.srcPkgs, nil
}
func (m *mockCollector) AvailableUpdates(_ context.Context) (map[string]string, error) {
	return m.updates, nil
}
func (m *mockCollector) OSFamily() string { return m.family }
func (m *mockCollector) Release() string  { return m.release }

func TestScan(t *testing.T) {
	mockResult := ScanResult{
		ServerName: "test-host",
		Family:     "debian",
		Release:    "12",
		ScannedCves: map[string]VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				AffectedPackages: []AffectedPackage{
					{Name: "openssl", NotFixedYet: false},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vuls" {
			t.Errorf("expected path /vuls, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		var req ScanRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.Family != "debian" {
			t.Errorf("expected family debian, got %s", req.Family)
		}
		if len(req.Packages) != 1 {
			t.Errorf("expected 1 package, got %d", len(req.Packages))
		}
		if pkg, ok := req.Packages["openssl"]; !ok || pkg.Version != "3.0.13-1" {
			t.Errorf("unexpected packages: %v", req.Packages)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{mockResult})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family:  "debian",
		release: "12",
		pkgs:    "openssl\tii \t3.0.13-1\n",
	}

	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.ScannedCves) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(result.ScannedCves))
	}
	if _, ok := result.ScannedCves["CVE-2024-1234"]; !ok {
		t.Error("expected CVE-2024-1234 in results")
	}
}

func TestScan_ContentTypeHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{{}})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\tii \t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScan_RequestBody(t *testing.T) {
	var received ScanRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{{}})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{
		URL:      server.URL,
		CertFile: "../../mocks/server-cert.pem",
		KeyFile:  "../../mocks/server-cert.pem",
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "redhat", release: "9", pkgs: "bash\tii \t5.2.21\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if received.Family != "redhat" {
		t.Errorf("expected family redhat, got %s", received.Family)
	}
	if received.Release != "9" {
		t.Errorf("expected release 9, got %s", received.Release)
	}
	if len(received.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(received.Packages))
	}
	if pkg, ok := received.Packages["bash"]; !ok || pkg.Version != "5.2.21" {
		t.Errorf("unexpected packages: %v", received.Packages)
	}
	if received.ServerName == "" {
		t.Error("expected non-empty ServerName (hostname)")
	}
}

func TestScan_SendsSrcPackages(t *testing.T) {
	var received ScanRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{{}})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family:  "ubuntu",
		release: "24.04",
		pkgs:    "bash\tii \t5.2.21\nlibssl3\tii \t3.0.13\n",
		srcPkgs: "bash\t5.2.21\tbash\tii \nopenssl\t3.0.13\tlibssl3\tii \n",
		updates: map[string]string{"bash": "5.3"},
	}

	_, err = sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if len(received.SrcPackages) != 2 {
		t.Errorf("expected 2 source packages, got %d", len(received.SrcPackages))
	}
	if sp, ok := received.SrcPackages["openssl"]; !ok {
		t.Error("expected openssl in srcPackages")
	} else if len(sp.BinaryNames) != 1 || sp.BinaryNames[0] != "libssl3" {
		t.Errorf("unexpected openssl binaries: %v", sp.BinaryNames)
	}

	// Verify newVersion was merged
	if pkg, ok := received.Packages["bash"]; !ok {
		t.Error("expected bash in packages")
	} else if pkg.NewVersion != "5.3" {
		t.Errorf("expected bash newVersion 5.3, got %s", pkg.NewVersion)
	}
}

func TestScan_MergesBackNewVersion(t *testing.T) {
	// Server response has empty newVersion (as real vuls server does).
	mockResult := ScanResult{
		ServerName: "test-host",
		Family:     "ubuntu",
		Release:    "22.04",
		Packages: Packages{
			"bash":    {Name: "bash", Version: "5.1"},
			"openssl": {Name: "openssl", Version: "3.0.2"},
		},
		ScannedCves: map[string]VulnInfo{
			"CVE-2024-5678": {
				CveID: "CVE-2024-5678",
				AffectedPackages: []AffectedPackage{
					{Name: "bash", NotFixedYet: false, FixedIn: "5.2"},
				},
			},
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
		family:  "ubuntu",
		release: "22.04",
		pkgs:    "bash\tii \t5.1\nopenssl\tii \t3.0.2\n",
		updates: map[string]string{"bash": "5.2", "openssl": "3.0.14"},
	}

	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	// Verify newVersion was merged back from local updates
	if pkg, ok := result.Packages["bash"]; !ok {
		t.Error("expected bash in result packages")
	} else if pkg.NewVersion != "5.2" {
		t.Errorf("expected bash newVersion 5.2, got %q", pkg.NewVersion)
	}

	if pkg, ok := result.Packages["openssl"]; !ok {
		t.Error("expected openssl in result packages")
	} else if pkg.NewVersion != "3.0.14" {
		t.Errorf("expected openssl newVersion 3.0.14, got %q", pkg.NewVersion)
	}

	// Verify fixedIn was deserialized
	cve := result.ScannedCves["CVE-2024-5678"]
	if len(cve.AffectedPackages) != 1 {
		t.Fatalf("expected 1 affected package, got %d", len(cve.AffectedPackages))
	}
	if cve.AffectedPackages[0].FixedIn != "5.2" {
		t.Errorf("expected fixedIn 5.2, got %q", cve.AffectedPackages[0].FixedIn)
	}
}

func TestScan_CollectorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("server should not be called when collector fails")
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family: "debian",
		err:    io.ErrUnexpectedEOF,
	}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error when collector fails")
	}
	// A local collector fault must not be reported as an upstream outage —
	// the daemon exits on ErrUpstream and would crash-loop on this.
	if errors.Is(err, ErrUpstream) {
		t.Errorf("collector error must not match ErrUpstream, got %v", err)
	}
}

func TestScan_UpstreamStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = sc.Scan(context.Background(), &mockCollector{family: "debian", release: "12"})
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("expected ErrUpstream for a 502 response, got %v", err)
	}
}

func TestScan_UpstreamDialError(t *testing.T) {
	// Start and immediately stop a server so the address refuses connections.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	sc, err := New(config.VulsServer{URL: url}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = sc.Scan(context.Background(), &mockCollector{family: "debian", release: "12"})
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("expected ErrUpstream for a refused connection, got %v", err)
	}
}

func TestNew_NoTLS(t *testing.T) {
	sc, err := New(config.VulsServer{URL: "http://localhost:5515"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if sc.serverURL != "http://localhost:5515" {
		t.Errorf("expected URL http://localhost:5515, got %s", sc.serverURL)
	}
}

func TestNew_CustomTimeout(t *testing.T) {
	sc, err := New(config.VulsServer{
		URL:     "http://localhost:5515",
		Timeout: config.Duration{Duration: 2 * time.Minute},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if sc.client.Timeout != 2*time.Minute {
		t.Errorf("expected timeout 2m, got %s", sc.client.Timeout)
	}
}

func TestNew_DefaultTimeout(t *testing.T) {
	sc, err := New(config.VulsServer{URL: "http://localhost:5515"}, "")
	if err != nil {
		t.Fatal(err)
	}
	const defaultTimeout = 5 * time.Minute
	if sc.client.Timeout != defaultTimeout {
		t.Errorf("expected default timeout %s, got %s", defaultTimeout, sc.client.Timeout)
	}
}

func TestNew_InvalidCertFile(t *testing.T) {
	_, err := New(config.VulsServer{
		URL:      "https://localhost:5515",
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}, "")
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
}

func TestBuildTLSConfig_InvalidCertFile(t *testing.T) {
	_, err := buildTLSConfig(config.VulsServer{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	// Create a minimal self-signed cert+key for the test
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)

	_, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)
	caFile := writeTempFile(t, "not a PEM certificate")

	_, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid CA PEM content")
	}
}

func TestBuildTLSConfig_ValidCertNoCA(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)

	tlsCfg, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs != nil {
		t.Error("expected nil RootCAs when no CA file specified")
	}
}

func TestBuildTLSConfig_ValidCertWithCA(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)
	caFile := writeTempFile(t, certPEM) // reuse cert as CA for test

	tlsCfg, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs when CA file specified")
	}
}

// nodeScanServer captures the payload the scanner posts and answers with a
// minimal result, so a test can assert on what was sent.
func nodeScanServer(t *testing.T, payload *map[string]any) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(payload); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]ScanResult{{ServerName: "demo.example"}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
}

func TestScan_SendsNodeNameInOptional(t *testing.T) {
	var payload map[string]any
	server := nodeScanServer(t, &payload)
	defer server.Close()

	sc := certScanner(t, server.URL, "worker-1")

	coll := &mockCollector{family: "debian", release: "12", pkgs: "bash\tii\t5.2.15\n"}
	if _, err := sc.Scan(context.Background(), coll); err != nil {
		t.Fatal(err)
	}

	// The key is capitalised because that is the field vuls persists.
	optional, ok := payload["Optional"].(map[string]any)
	if !ok {
		t.Fatalf("expected an Optional map in the payload, got %v", payload["Optional"])
	}
	if optional[optionalNodeName] != "worker-1" {
		t.Errorf("expected node name worker-1, got %v", optional[optionalNodeName])
	}
}

func TestScan_OmitsOptionalWithoutIdentity(t *testing.T) {
	var payload map[string]any
	server := nodeScanServer(t, &payload)
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL}, "")
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "bash\tii\t5.2.15\n"}
	if _, err := sc.Scan(context.Background(), coll); err != nil {
		t.Fatal(err)
	}

	if _, present := payload["Optional"]; present {
		t.Errorf("expected no Optional map without a certname or node name, got %v", payload["Optional"])
	}
}

func TestScan_SendsIdentity(t *testing.T) {
	var payload map[string]any
	server := nodeScanServer(t, &payload)
	defer server.Close()

	sc := certScanner(t, server.URL, "worker-1")

	coll := &mockCollector{family: "debian", release: "12", pkgs: "bash\tii\t5.2.15\n"}
	if _, err := sc.Scan(context.Background(), coll); err != nil {
		t.Fatal(err)
	}

	if payload["serverName"] != "worker-1@test" {
		t.Errorf("expected serverName worker-1@test, got %v", payload["serverName"])
	}
	optional, ok := payload["Optional"].(map[string]any)
	if !ok {
		t.Fatalf("expected an Optional map in the payload, got %v", payload["Optional"])
	}
	if optional[optionalCertname] != "test" {
		t.Errorf("expected certname test, got %v", optional[optionalCertname])
	}
}

func TestScanner_Identity(t *testing.T) {
	tests := []struct {
		name           string
		certname       string
		nodeName       string
		wantServerName string
		wantOptional   map[string]any
	}{
		{
			name: "host", certname: "web01.demo", wantServerName: "web01.demo",
			wantOptional: map[string]any{optionalCertname: "web01.demo"},
		},
		{
			name: "node", certname: "demo.example", nodeName: "worker-1", wantServerName: "worker-1@demo.example",
			wantOptional: map[string]any{optionalCertname: "demo.example", optionalNodeName: "worker-1"},
		},
		{name: "neither"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{certname: tt.certname, nodeName: tt.nodeName}
			if got := s.serverName(); got != tt.wantServerName {
				t.Errorf("expected serverName %q, got %q", tt.wantServerName, got)
			}
			if got := s.optional(); !reflect.DeepEqual(got, tt.wantOptional) {
				t.Errorf("expected Optional %v, got %v", tt.wantOptional, got)
			}
		})
	}
}

func TestNew_NodeNeedsCertificate(t *testing.T) {
	if _, err := New(config.VulsServer{URL: "https://vuls.example"}, "worker-1"); err == nil {
		t.Error("expected an error for a node without a client certificate")
	}
}

// certScanner builds a scanner with a client certificate, which
// generateTestCert names "test".
func certScanner(t *testing.T, url, nodeName string) *Scanner {
	t.Helper()

	certPEM, keyPEM := generateTestCert(t)
	sc, err := New(config.VulsServer{
		URL:      url,
		CertFile: writeTempFile(t, certPEM),
		KeyFile:  writeTempFile(t, keyPEM),
	}, nodeName)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}
