package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDomainsFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "single domain",
			input: "example.com",
			want:  []string{"example.com"},
		},
		{
			name:  "multiple domains",
			input: "example.com,google.com,github.com",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "domains with ports",
			input: "example.com:443,google.com:8080",
			want:  []string{"example.com:443", "google.com:8080"},
		},
		{
			name:  "domains with spaces",
			input: " example.com , google.com , github.com ",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "domains with empty entries",
			input: "example.com,,google.com,",
			want:  []string{"example.com", "google.com"},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "only commas",
			input:   ",,,",
			wantErr: true,
		},
		{
			name:    "invalid domain format with spaces",
			input:   "example.com,host with spaces",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDomainsFromString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseDomainsFromString() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseDomainsFromString() unexpected error: %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ParseDomainsFromString() length = %d, want %d", len(got), len(tt.want))
				return
			}

			for i, domain := range got {
				if domain != tt.want[i] {
					t.Errorf("ParseDomainsFromString()[%d] = %v, want %v", i, domain, tt.want[i])
				}
			}
		})
	}
}

func TestParseDomainsFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "ssl-cert-domain-file-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	validDomainsPath := filepath.Join(tempDir, "domains.txt")
	validDomainsContent := " example.com \n\n google.com:443 \n   \ngithub.com\n"
	if err := os.WriteFile(validDomainsPath, []byte(validDomainsContent), 0644); err != nil {
		t.Fatalf("Failed to write valid domains file: %v", err)
	}

	got, err := ParseDomainsFromFile(validDomainsPath)
	if err != nil {
		t.Errorf("ParseDomainsFromFile() unexpected error: %v", err)
	}

	want := []string{"example.com", "google.com:443", "github.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseDomainsFromFile() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseDomainsFromFile()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	emptyDomainsPath := filepath.Join(tempDir, "empty-domains.txt")
	emptyDomainsContent := "\n  \n\t\r\n"
	if err := os.WriteFile(emptyDomainsPath, []byte(emptyDomainsContent), 0644); err != nil {
		t.Fatalf("Failed to write empty domains file: %v", err)
	}

	_, err = ParseDomainsFromFile(emptyDomainsPath)
	if err == nil {
		t.Error("ParseDomainsFromFile() expected error for empty domains file but got none")
	}

	invalidDomainsPath := filepath.Join(tempDir, "invalid-domains.txt")
	invalidDomainsContent := "example.com\ninvalid domain\n"
	if err := os.WriteFile(invalidDomainsPath, []byte(invalidDomainsContent), 0644); err != nil {
		t.Fatalf("Failed to write invalid domains file: %v", err)
	}

	_, err = ParseDomainsFromFile(invalidDomainsPath)
	if err == nil {
		t.Error("ParseDomainsFromFile() expected error for invalid domains file but got none")
	}

	_, err = ParseDomainsFromFile("/non/existent/domains.txt")
	if err == nil {
		t.Error("ParseDomainsFromFile() expected error for non-existent file but got none")
	}

	_, err = ParseDomainsFromFile("")
	if err == nil {
		t.Error("ParseDomainsFromFile() expected error for empty path but got none")
	}
}

func TestParseDomainsFromFileWithRange(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ssl-cert-domain-file-range-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	validPath := filepath.Join(tempDir, "domains-range.txt")
	validContent := "first.example.com\n\nsecond.example.com:443\nthird.example.com\nfourth.example.com\n"
	if err := os.WriteFile(validPath, []byte(validContent), 0644); err != nil {
		t.Fatalf("Failed to write domains range file: %v", err)
	}

	got, err := ParseDomainsFromFileWithRange(validPath, 1, 3)
	if err != nil {
		t.Fatalf("ParseDomainsFromFileWithRange() unexpected error: %v", err)
	}

	want := []string{"second.example.com:443", "third.example.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseDomainsFromFileWithRange() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseDomainsFromFileWithRange()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	got, err = ParseDomainsFromFileWithRange(validPath, 3, 2)
	if err != nil {
		t.Fatalf("ParseDomainsFromFileWithRange() unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "third.example.com" || got[1] != "fourth.example.com" {
		t.Errorf("ParseDomainsFromFileWithRange() with skip=3,limit=2 got %v", got)
	}

	_, err = ParseDomainsFromFileWithRange(validPath, 100, 1)
	if err == nil {
		t.Error("ParseDomainsFromFileWithRange() expected error when selected range has no valid domains but got none")
	}

	invalidPath := filepath.Join(tempDir, "domains-invalid-range.txt")
	invalidContent := "first.example.com\nsecond.example.com\ninvalid domain\n"
	if err := os.WriteFile(invalidPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write invalid domains file: %v", err)
	}

	_, err = ParseDomainsFromFileWithRange(invalidPath, 1, 2)
	if err == nil {
		t.Fatal("ParseDomainsFromFileWithRange() expected error for invalid domain but got none")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("ParseDomainsFromFileWithRange() error should reference original line number, got: %v", err)
	}

	_, err = ParseDomainsFromFileWithRange(validPath, -1, 1)
	if err == nil {
		t.Error("ParseDomainsFromFileWithRange() expected error for negative skip but got none")
	}

	_, err = ParseDomainsFromFileWithRange(validPath, 1, -1)
	if err == nil {
		t.Error("ParseDomainsFromFileWithRange() expected error for negative limit but got none")
	}
}

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid hostname",
			input: "example.com",
		},
		{
			name:  "valid hostname with port",
			input: "example.com:443",
		},
		{
			name:  "hostname with subdomain",
			input: "www.example.com",
		},
		{
			name:  "IPv6 address with brackets",
			input: "[::1]:8080",
		},
		{
			name:  "IPv6 address with brackets no port",
			input: "[::1]",
		},
		{
			name:  "IPv6 address without brackets",
			input: "2001:db8::1",
		},
		{
			name:  "valid port range",
			input: "example.com:65535",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "only spaces",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "hostname with spaces",
			input:   "exam ple.com",
			wantErr: true,
		},
		{
			name:    "empty hostname with port",
			input:   ":443",
			wantErr: true,
		},
		{
			name:    "invalid port - non-numeric",
			input:   "example.com:abc",
			wantErr: true,
		},
		{
			name:    "invalid port - too low",
			input:   "example.com:0",
			wantErr: true,
		},
		{
			name:    "invalid port - too high",
			input:   "example.com:65536",
			wantErr: true,
		},
		{
			name:    "IPv6 missing closing bracket",
			input:   "[::1:8080",
			wantErr: true,
		},
		{
			name:    "IPv6 empty address",
			input:   "[]",
			wantErr: true,
		},
		{
			name:    "IPv6 invalid format after bracket",
			input:   "[::1]invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHost(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateHost() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("validateHost() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "ssl-cert-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test valid config file
	validConfigPath := filepath.Join(tempDir, "valid.yaml")
	validConfigContent := `hosts:
  - example.com
  - google.com:443
  - github.com
`
	if err := os.WriteFile(validConfigPath, []byte(validConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write valid config file: %v", err)
	}

	config, err := LoadConfig(validConfigPath)
	if err != nil {
		t.Errorf("LoadConfig() unexpected error: %v", err)
	}
	if config == nil {
		t.Fatal("LoadConfig() returned nil config")
	}
	if len(config.Hosts) != 3 {
		t.Errorf("LoadConfig() hosts count = %d, want 3", len(config.Hosts))
	}

	// Test empty config file
	emptyConfigPath := filepath.Join(tempDir, "empty.yaml")
	if err := os.WriteFile(emptyConfigPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write empty config file: %v", err)
	}

	_, err = LoadConfig(emptyConfigPath)
	if err == nil {
		t.Error("LoadConfig() expected error for empty file but got none")
	}

	// Test invalid YAML
	invalidConfigPath := filepath.Join(tempDir, "invalid.yaml")
	invalidConfigContent := `hosts:
  - example.com
  invalid yaml content
`
	if err := os.WriteFile(invalidConfigPath, []byte(invalidConfigContent), 0644); err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = LoadConfig(invalidConfigPath)
	if err == nil {
		t.Error("LoadConfig() expected error for invalid YAML but got none")
	}

	// Test non-existent file
	_, err = LoadConfig("/non/existent/file.yaml")
	if err == nil {
		t.Error("LoadConfig() expected error for non-existent file but got none")
	}

	// Test empty path
	_, err = LoadConfig("")
	if err == nil {
		t.Error("LoadConfig() expected error for empty path but got none")
	}
}

func TestAppConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AppConfig
		wantErr bool
	}{
		{
			name: "valid config with config file",
			config: AppConfig{
				ConfigFile:   "config.yaml",
				Timeout:      5,
				OutputFormat: "table",
			},
		},
		{
			name: "valid config with domains",
			config: AppConfig{
				Domains:      "example.com,google.com",
				Timeout:      10,
				OutputFormat: "json",
			},
		},
		{
			name: "valid config with domains file",
			config: AppConfig{
				DomainsFile:      "domains.txt",
				DomainsFileSkip:  10,
				DomainsFileLimit: 20,
				Timeout:          10,
				OutputFormat:     "json",
			},
		},
		{
			name: "valid config with empty output format",
			config: AppConfig{
				Domains: "example.com",
				Timeout: 5,
			},
		},
		{
			name: "no host source",
			config: AppConfig{
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "both config and domains",
			config: AppConfig{
				ConfigFile: "config.yaml",
				Domains:    "example.com",
				Timeout:    5,
			},
			wantErr: true,
		},
		{
			name: "config and domains file",
			config: AppConfig{
				ConfigFile:  "config.yaml",
				DomainsFile: "domains.txt",
				Timeout:     5,
			},
			wantErr: true,
		},
		{
			name: "domains and domains file",
			config: AppConfig{
				Domains:     "example.com",
				DomainsFile: "domains.txt",
				Timeout:     5,
			},
			wantErr: true,
		},
		{
			name: "skip without domains file",
			config: AppConfig{
				Domains:         "example.com",
				DomainsFileSkip: 1,
				Timeout:         5,
			},
			wantErr: true,
		},
		{
			name: "limit without domains file",
			config: AppConfig{
				Domains:          "example.com",
				DomainsFileLimit: 1,
				Timeout:          5,
			},
			wantErr: true,
		},
		{
			name: "negative skip",
			config: AppConfig{
				DomainsFile:     "domains.txt",
				DomainsFileSkip: -1,
				Timeout:         5,
			},
			wantErr: true,
		},
		{
			name: "negative limit",
			config: AppConfig{
				DomainsFile:      "domains.txt",
				DomainsFileLimit: -1,
				Timeout:          5,
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			config: AppConfig{
				Domains: "example.com",
				Timeout: 0,
			},
			wantErr: true,
		},
		{
			name: "invalid output format",
			config: AppConfig{
				Domains:      "example.com",
				Timeout:      5,
				OutputFormat: "xml",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("AppConfig.Validate() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("AppConfig.Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAppConfig_GetHosts_DomainsFileRange(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ssl-cert-get-hosts-range-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	domainsPath := filepath.Join(tempDir, "domains.txt")
	content := "alpha.example.com\nbeta.example.com\ngamma.example.com\ndelta.example.com\n"
	if err := os.WriteFile(domainsPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write domains file: %v", err)
	}

	cfg := AppConfig{
		DomainsFile:      domainsPath,
		DomainsFileSkip:  1,
		DomainsFileLimit: 2,
		Timeout:          5,
		OutputFormat:     "table",
	}

	got, err := cfg.GetHosts()
	if err != nil {
		t.Fatalf("GetHosts() unexpected error: %v", err)
	}

	want := []string{"beta.example.com", "gamma.example.com"}
	if len(got) != len(want) {
		t.Fatalf("GetHosts() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("GetHosts()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
