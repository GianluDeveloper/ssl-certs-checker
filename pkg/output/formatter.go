package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/guessi/ssl-certs-checker/pkg/cert"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

const defaultOutputFileMode = 0o644

// NewFormatter creates a new output formatter
func New() *Formatter {
	return &Formatter{}
}

// Format formats the certificate results according to the specified format
func (f *Formatter) Format(result *cert.Result, format string) error {
	return f.FormatTo(result, format, "")
}

// FormatTo formats certificate results and writes to stdout or a file when outputFile is set.
func (f *Formatter) FormatTo(result *cert.Result, format, outputFile string) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	if outputFile != "" && strings.TrimSpace(outputFile) == "" {
		return fmt.Errorf("output file path cannot be empty")
	}

	output, err := f.render(result, format)
	if err != nil {
		return err
	}

	if outputFile == "" {
		fmt.Print(output)
		return nil
	}

	if err := writeOutputFile(outputFile, []byte(output)); err != nil {
		return fmt.Errorf("error writing output file: %w", err)
	}

	return nil
}

func (f *Formatter) render(result *cert.Result, format string) (string, error) {
	switch format {
	case "json":
		return f.formatJSON(result)
	case "yaml":
		return f.formatYAML(result)
	case "table", "":
		return f.formatTable(result)
	default:
		return "", fmt.Errorf("unsupported output format: %s", format)
	}
}

// formatJSON outputs the results in JSON format
func (f *Formatter) formatJSON(result *cert.Result) (string, error) {
	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %w", err)
	}

	return ensureTrailingNewline(string(jsonOutput)), nil
}

// formatYAML outputs the results in YAML format
func (f *Formatter) formatYAML(result *cert.Result) (string, error) {
	yamlOutput, err := yaml.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("error marshaling YAML: %w", err)
	}

	return ensureTrailingNewline(string(yamlOutput)), nil
}

// formatTable outputs the results in table format
func (f *Formatter) formatTable(result *cert.Result) (string, error) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{
		"Host",
		"Common Name",
		"DNS Names",
		"Not Before",
		"Not After",
		"PublicKeyAlgorithm",
		"Issuer",
	})

	for _, certInfo := range result.Certificates {
		dnsNames := ""
		if len(certInfo.DNSNames) > 0 {
			dnsNames = strings.Join(certInfo.DNSNames, "\n")
		}

		t.AppendRows([]table.Row{{
			certInfo.Host,
			certInfo.CommonName,
			dnsNames,
			certInfo.NotBefore,
			certInfo.NotAfter,
			certInfo.PublicKeyAlgorithm,
			certInfo.Issuer,
		}})
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\nErrors encountered:\n")
		for _, errInfo := range result.Errors {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", errInfo.Host, errInfo.Error)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	t.Style().Format.Header = text.FormatDefault
	output := ensureTrailingNewline(t.Render())

	return output, nil
}

func ensureTrailingNewline(content string) string {
	if strings.HasSuffix(content, "\n") {
		return content
	}

	return content + "\n"
}

func writeOutputFile(path string, data []byte) error {
	tmpDir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(tmpDir, ".ssl-certs-checker-output-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary output file: %w", err)
	}

	tmpName := tmpFile.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	fileMode := os.FileMode(defaultOutputFileMode)
	info, statErr := os.Stat(path)
	if statErr == nil {
		fileMode = info.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to inspect output file: %w", statErr)
	}

	if err := tmpFile.Chmod(fileMode); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to set output file permissions: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write output data: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to flush output data: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to replace output file: %w", err)
	}

	removeTmp = false
	return nil
}
