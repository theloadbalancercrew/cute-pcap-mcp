package config

import "testing"

func TestNormalizeAppliesAnalysisDefaults(t *testing.T) {
	cfg, err := Normalize(Config{
		AllowedArtifactDirs: []string{"."},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Analysis.CommandTimeoutSeconds != 20 {
		t.Fatalf("CommandTimeoutSeconds = %d", cfg.Analysis.CommandTimeoutSeconds)
	}
	if cfg.Analysis.MaxStdoutBytes != 200000 {
		t.Fatalf("MaxStdoutBytes = %d", cfg.Analysis.MaxStdoutBytes)
	}
	if cfg.Analysis.MaxPacketRows != 200 {
		t.Fatalf("MaxPacketRows = %d", cfg.Analysis.MaxPacketRows)
	}
	if cfg.Analysis.MaxASCIIStrings != 200 {
		t.Fatalf("MaxASCIIStrings = %d", cfg.Analysis.MaxASCIIStrings)
	}
	if cfg.Analysis.MaxASCIIBytes != 200000 {
		t.Fatalf("MaxASCIIBytes = %d", cfg.Analysis.MaxASCIIBytes)
	}
	if cfg.Analysis.MaxZeekRecordsPerLog != 100 {
		t.Fatalf("MaxZeekRecordsPerLog = %d", cfg.Analysis.MaxZeekRecordsPerLog)
	}
}

func TestNormalizeRejectsInvalidAnalysisLimits(t *testing.T) {
	_, err := Normalize(Config{
		AllowedArtifactDirs: []string{"."},
		Analysis: AnalysisConfig{
			MaxPacketRows: 10001,
		},
	})
	if err == nil {
		t.Fatal("Normalize returned nil, want error")
	}
}
