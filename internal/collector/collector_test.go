package collector

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const (
	familyDebian = "debian"
	familyUbuntu = "ubuntu"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		expectedFamily  string
		expectedRelease string
	}{
		{
			name:            "Debian",
			content:         "ID=debian\nVERSION_ID=\"12\"\n",
			expectedFamily:  familyDebian,
			expectedRelease: "12",
		},
		{
			name:            "Ubuntu",
			content:         "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
			expectedFamily:  familyUbuntu,
			expectedRelease: "22.04",
		},
		{
			name:            "Rocky",
			content:         "ID=\"rocky\"\nVERSION_ID=\"9.3\"\n",
			expectedFamily:  "rocky",
			expectedRelease: "9.3",
		},
		{
			name:            "RHEL",
			content:         "ID=\"rhel\"\nVERSION_ID=\"9.2\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.2 (Plow)\"\n",
			expectedFamily:  "rhel",
			expectedRelease: "9.2",
		},
		{
			name:            "AlmaLinux",
			content:         "ID=\"almalinux\"\nVERSION_ID=\"9.3\"\n",
			expectedFamily:  "almalinux",
			expectedRelease: "9.3",
		},
		{
			name:            "Fedora",
			content:         "ID=fedora\nVERSION_ID=39\n",
			expectedFamily:  "fedora",
			expectedRelease: "39",
		},
		{
			name:            "CentOS",
			content:         "ID=\"centos\"\nVERSION_ID=\"7\"\n",
			expectedFamily:  "centos",
			expectedRelease: "7",
		},
		{
			name:            "SLES",
			content:         "ID=\"sles\"\nVERSION_ID=\"15.5\"\n",
			expectedFamily:  "sles",
			expectedRelease: "15.5",
		},
		{
			name:            "SUSE",
			content:         "ID=\"suse\"\nVERSION_ID=\"15.7\"\n",
			expectedFamily:  "suse",
			expectedRelease: "15.7",
		},
		{
			name:            "MissingVersionID",
			content:         "ID=debian\n",
			expectedFamily:  familyDebian,
			expectedRelease: "",
		},
		{
			name: "ExtraFields",
			content: "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n" +
				"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nHOME_URL=\"https://www.debian.org/\"\n",
			expectedFamily:  familyDebian,
			expectedRelease: "12",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tt.content)
			family, release, err := parseOSRelease(path)
			if err != nil {
				t.Fatal(err)
			}
			if family != tt.expectedFamily {
				t.Errorf("expected family %s, got %s", tt.expectedFamily, family)
			}
			if release != tt.expectedRelease {
				t.Errorf("expected release %s, got %s", tt.expectedRelease, release)
			}
		})
	}
}

func TestParseOSRelease_Errors(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		useFile bool
	}{
		{
			name:    "MissingID",
			content: "VERSION_ID=\"12\"\n",
			useFile: true,
		},
		{
			name:    "FileNotFound",
			path:    "/nonexistent/os-release",
			useFile: false,
		},
		{
			name:    "EmptyFile",
			content: "",
			useFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.useFile {
				path = writeTempFile(t, tt.content)
			}
			_, _, err := parseOSRelease(path)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDpkgCollector_OSFamily(t *testing.T) {
	c := &dpkgCollector{family: familyDebian, release: "12"}
	if c.OSFamily() != familyDebian {
		t.Errorf("expected %s, got %s", familyDebian, c.OSFamily())
	}
}

func TestDpkgCollector_Release(t *testing.T) {
	c := &dpkgCollector{family: familyDebian, release: "12"}
	if c.Release() != "12" {
		t.Errorf("expected 12, got %s", c.Release())
	}
}

func TestRpmCollector_OSFamily(t *testing.T) {
	c := &rpmCollector{family: "redhat", release: "9"}
	if c.OSFamily() != "redhat" {
		t.Errorf("expected redhat, got %s", c.OSFamily())
	}
}

func TestRpmCollector_Release(t *testing.T) {
	c := &rpmCollector{family: "redhat", release: "9"}
	if c.Release() != "9" {
		t.Errorf("expected 9, got %s", c.Release())
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDatabaseArgs(t *testing.T) {
	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{
			name: "DpkgLocal",
			got:  (&dpkgCollector{}).dbArgs("-W"),
			want: []string{"-W"},
		},
		{
			name: "DpkgMounted",
			got:  (&dpkgCollector{adminDir: "/host/var/lib/dpkg"}).dbArgs("-W"),
			want: []string{"--admindir=/host/var/lib/dpkg", "-W"},
		},
		{
			name: "RpmLocal",
			got:  rpmDBArgs("", "-qa"),
			want: []string{"-qa"},
		},
		{
			name: "RpmMounted",
			got:  rpmDBArgs("/host/var/lib/rpm", "-qa"),
			want: []string{"--dbpath=/host/var/lib/rpm", "-qa"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !slices.Equal(tt.got, tt.want) {
				t.Errorf("expected args %v, got %v", tt.want, tt.got)
			}
		})
	}
}

func TestDetectOSUnderHostRoot(t *testing.T) {
	root := writeTempHostRoot(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\n")

	id, release, err := DetectOS(root)
	if err != nil {
		t.Fatal(err)
	}
	if id != familyUbuntu {
		t.Errorf("expected id %s, got %s", familyUbuntu, id)
	}
	if release != "24.04" {
		t.Errorf("expected release 24.04, got %s", release)
	}
}

func TestNewUnderHostRoot(t *testing.T) {
	tests := []struct {
		name      string
		osRelease string
		wantDB    string
	}{
		{name: "Debian", osRelease: "ID=ubuntu\nVERSION_ID=\"24.04\"\n", wantDB: dpkgAdminDir},
		{name: "RedHat", osRelease: "ID=rocky\nVERSION_ID=\"9.4\"\n", wantDB: rpmDBDir},
		{name: "SUSE", osRelease: "ID=sles\nVERSION_ID=\"15.6\"\n", wantDB: rpmDBDir},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTempHostRoot(t, tt.osRelease)

			coll, err := New(root)
			if err != nil {
				t.Fatal(err)
			}

			var got string
			switch c := coll.(type) {
			case *dpkgCollector:
				got = c.adminDir
			case *rpmCollector:
				got = c.dbPath
			case *zypperCollector:
				got = c.dbPath
			default:
				t.Fatalf("unexpected collector %T", coll)
			}

			if want := filepath.Join(root, tt.wantDB); got != want {
				t.Errorf("expected database %s, got %s", want, got)
			}
		})
	}
}

func writeTempHostRoot(t *testing.T, osRelease string) string {
	t.Helper()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte(osRelease), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}
