package output

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guessi/ssl-certs-checker/pkg/cert"
)

func TestNewFormatter(t *testing.T) {
	formatter := New()
	if formatter == nil {
		t.Fatal("NewFormatter() returned nil")
	}
}

func TestFormatter_Format_JSON(t *testing.T) {
	formatter := New()

	// Create test data
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:               "example.com:443",
				CommonName:         "example.com",
				DNSNames:           []string{"example.com", "www.example.com"},
				NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				PublicKeyAlgorithm: "RSA",
				Issuer:             "Test CA",
			},
		},
		Errors: []cert.ErrorInfo{
			{
				Host:  "invalid.com:443",
				Error: "connection failed",
			},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Format(result, "json")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Errorf("Format() unexpected error: %v", err)
	}

	// Read captured output
	output, _ := io.ReadAll(r)

	// Verify it's valid JSON
	var jsonResult cert.Result
	if err := json.Unmarshal(output, &jsonResult); err != nil {
		t.Errorf("Format() produced invalid JSON: %v", err)
	}

	// Verify content
	if len(jsonResult.Certificates) != 1 {
		t.Errorf("JSON output certificates count = %d, want 1", len(jsonResult.Certificates))
	}

	if len(jsonResult.Errors) != 1 {
		t.Errorf("JSON output errors count = %d, want 1", len(jsonResult.Errors))
	}
}

func TestFormatter_Format_Table(t *testing.T) {
	formatter := New()

	// Create test data
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:               "example.com:443",
				CommonName:         "example.com",
				DNSNames:           []string{"example.com", "www.example.com"},
				NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				PublicKeyAlgorithm: "RSA",
				Issuer:             "Test CA",
			},
		},
		Errors: []cert.ErrorInfo{
			{
				Host:  "invalid.com:443",
				Error: "connection failed",
			},
		},
	}

	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	err := formatter.Format(result, "table")

	// Restore stdout and stderr
	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	if err != nil {
		t.Errorf("Format() unexpected error: %v", err)
	}

	// Read captured outputs
	stdoutOutput, _ := io.ReadAll(rOut)
	stderrOutput, _ := io.ReadAll(rErr)

	// Verify table contains expected data
	tableStr := string(stdoutOutput)
	if !strings.Contains(tableStr, "example.com:443") {
		t.Error("Table output should contain host information")
	}
	if !strings.Contains(tableStr, "example.com") {
		t.Error("Table output should contain common name")
	}
	if !strings.Contains(tableStr, "RSA") {
		t.Error("Table output should contain public key algorithm")
	}

	// Verify errors are printed to stderr
	errorStr := string(stderrOutput)
	if !strings.Contains(errorStr, "invalid.com:443") {
		t.Error("Error output should contain error host")
	}
	if !strings.Contains(errorStr, "connection failed") {
		t.Error("Error output should contain error message")
	}
}

func TestFormatter_Format_EmptyResult(t *testing.T) {
	formatter := New()

	// Create empty result
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{},
		Errors:       []cert.ErrorInfo{},
	}

	// Test JSON format
	err := formatter.Format(result, "json")
	if err != nil {
		t.Errorf("Format() with empty result should not error: %v", err)
	}

	// Test table format
	err = formatter.Format(result, "table")
	if err != nil {
		t.Errorf("Format() with empty result should not error: %v", err)
	}
}

func TestFormatter_Format_InvalidFormat(t *testing.T) {
	formatter := New()

	result := &cert.Result{
		Certificates: []cert.CertificateInfo{},
		Errors:       []cert.ErrorInfo{},
	}

	err := formatter.Format(result, "xml")
	if err == nil {
		t.Error("Format() should return error for unsupported format")
	}

	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("Error message should mention unsupported format, got: %v", err)
	}
}

func TestFormatter_Format_DefaultFormat(t *testing.T) {
	formatter := New()

	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:       "example.com:443",
				CommonName: "example.com",
			},
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Test empty format (should default to table)
	err := formatter.Format(result, "")

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Errorf("Format() with empty format should not error: %v", err)
	}

	// Read captured output
	output, _ := io.ReadAll(r)
	tableStr := string(output)

	// Should produce table output
	if !strings.Contains(tableStr, "example.com:443") {
		t.Error("Default format should produce table output")
	}
}

func TestFormatter_FormatTo_JSONFile(t *testing.T) {
	formatter := New()
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:       "example.com:443",
				CommonName: "example.com",
			},
		},
		Errors: []cert.ErrorInfo{
			{
				Host:  "invalid.com:443",
				Error: "connection failed",
			},
		},
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	if err := formatter.FormatTo(result, "json", outputPath); err != nil {
		t.Fatalf("FormatTo() unexpected error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var got cert.Result
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Output file should contain valid JSON: %v", err)
	}

	if len(got.Certificates) != 1 {
		t.Errorf("JSON output certificates count = %d, want 1", len(got.Certificates))
	}

	if len(got.Errors) != 1 {
		t.Errorf("JSON output errors count = %d, want 1", len(got.Errors))
	}
}

func TestFormatter_FormatTo_TableFile(t *testing.T) {
	formatter := New()
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:               "example.com:443",
				CommonName:         "example.com",
				DNSNames:           []string{"example.com", "www.example.com"},
				NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				PublicKeyAlgorithm: "RSA",
				Issuer:             "Test CA",
			},
		},
		Errors: []cert.ErrorInfo{
			{
				Host:  "invalid.com:443",
				Error: "connection failed",
			},
		},
	}

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	outputPath := filepath.Join(t.TempDir(), "result.txt")
	err := formatter.FormatTo(result, "table", outputPath)

	wErr.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("FormatTo() unexpected error: %v", err)
	}

	tableData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	tableStr := string(tableData)
	if !strings.Contains(tableStr, "example.com:443") {
		t.Error("Table output file should contain host information")
	}
	if !strings.Contains(tableStr, "RSA") {
		t.Error("Table output file should contain public key algorithm")
	}

	stderrData, _ := io.ReadAll(rErr)
	errorStr := string(stderrData)
	if !strings.Contains(errorStr, "invalid.com:443") {
		t.Error("Error output should contain error host")
	}
	if !strings.Contains(errorStr, "connection failed") {
		t.Error("Error output should contain error message")
	}
}

func TestFormatter_FormatTo_InvalidOutputFile(t *testing.T) {
	formatter := New()
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{},
		Errors:       []cert.ErrorInfo{},
	}

	err := formatter.FormatTo(result, "json", "   ")
	if err == nil {
		t.Fatal("FormatTo() should return error for blank output file path")
	}
}

func TestFormatter_FormatTo_NonExistentOutputDirectory(t *testing.T) {
	formatter := New()
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{},
		Errors:       []cert.ErrorInfo{},
	}

	outputPath := filepath.Join(t.TempDir(), "missing-dir", "result.json")
	err := formatter.FormatTo(result, "json", outputPath)
	if err == nil {
		t.Fatal("FormatTo() should return error for non-existent output directory")
	}
}

func TestFormatter_FormatTo_PreservesExistingFilePermissions(t *testing.T) {
	formatter := New()
	result := &cert.Result{
		Certificates: []cert.CertificateInfo{
			{
				Host:       "example.com:443",
				CommonName: "example.com",
			},
		},
	}

	outputPath := filepath.Join(t.TempDir(), "result.yaml")
	if err := os.WriteFile(outputPath, []byte("old"), 0600); err != nil {
		t.Fatalf("Failed to create existing output file: %v", err)
	}

	if err := formatter.FormatTo(result, "yaml", outputPath); err != nil {
		t.Fatalf("FormatTo() unexpected error: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat output file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("Output file permissions = %v, want %v", info.Mode().Perm(), os.FileMode(0600))
	}
}
