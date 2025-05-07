package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTarGz(t *testing.T) {
	// Test setup
	testTarGz := "../test_resources/test.tar.gz"
	testExtractDir := "/tmp/agent_builder.tmp339"

	// Clean up the test directory if it exists
	os.RemoveAll(testExtractDir)

	// Create the test directory
	err := os.MkdirAll(testExtractDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testExtractDir) // Clean up after test

	// Test the extraction
	err = ExtractTarGz(testTarGz, testExtractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz failed: %v", err)
	}

	// Verify the extracted file exists and has correct content
	extractedFile := filepath.Join(testExtractDir, "test.txt")
	if _, err := os.Stat(extractedFile); os.IsNotExist(err) {
		t.Error("Extracted file does not exist")
	}

	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}

	expectedContent := "This is a test file for tar.gz extraction"
	gotContent := strings.TrimSpace(string(content))
	expectedContent = strings.TrimSpace(expectedContent)

	if gotContent != expectedContent {
		t.Errorf("Extracted file content mismatch.\nExpected (%d bytes): %q\nGot (%d bytes): %q",
			len(expectedContent), expectedContent,
			len(gotContent), gotContent)
	}
}
