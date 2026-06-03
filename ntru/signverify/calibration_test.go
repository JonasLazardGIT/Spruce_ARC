package signverify

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func calibrationRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestCalibrateMeasuredBetaDeterministic(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := calibrationRepoRoot(t)
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	paths := SignPaths{
		ParamsPath:    "internal/source_data/Parameters.json",
		BFile:         "internal/source_data/Bmatrix.intgenisis_profile_b.json",
		PublicKeyPath: "ntru_keys/public.json",
		PrivatePath:   "ntru_keys/private.json",
	}
	for _, path := range []string{paths.ParamsPath, paths.BFile, paths.PublicKeyPath, paths.PrivatePath} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("skipping calibration without generated signing artifact %s: %v", path, err)
		}
	}
	gotA, err := CalibrateMeasuredBeta(paths, 4, 256, defaultOpts)
	if err != nil {
		t.Fatalf("calibrate A: %v", err)
	}
	gotB, err := CalibrateMeasuredBeta(paths, 4, 256, defaultOpts)
	if err != nil {
		t.Fatalf("calibrate B: %v", err)
	}
	if gotA.Samples != 4 || gotB.Samples != 4 {
		t.Fatalf("unexpected sample count: A=%d B=%d", gotA.Samples, gotB.Samples)
	}
	if gotA.Alpha <= 0 || gotB.Alpha <= 0 {
		t.Fatalf("non-positive alpha: A=%f B=%f", gotA.Alpha, gotB.Alpha)
	}
	if gotA.BatchMax <= 0 || gotB.BatchMax <= 0 {
		t.Fatalf("non-positive batch max: A=%d B=%d", gotA.BatchMax, gotB.BatchMax)
	}
	if gotA.BatchMaxIndex < 0 || gotA.BatchMaxIndex >= gotA.Samples {
		t.Fatalf("A batch max index=%d outside samples=%d", gotA.BatchMaxIndex, gotA.Samples)
	}
	if gotB.BatchMaxIndex < 0 || gotB.BatchMaxIndex >= gotB.Samples {
		t.Fatalf("B batch max index=%d outside samples=%d", gotB.BatchMaxIndex, gotB.Samples)
	}
	if gotA.Alpha != gotB.Alpha || gotA.BatchMax != gotB.BatchMax {
		t.Fatalf("non-deterministic calibration summary: A=%+v B=%+v", gotA, gotB)
	}
	if gotA.BatchMaxIndex != gotB.BatchMaxIndex {
		t.Fatalf("non-deterministic batch max index: A=%d B=%d", gotA.BatchMaxIndex, gotB.BatchMaxIndex)
	}
	if len(gotA.PerSample) != len(gotB.PerSample) {
		t.Fatalf("sample length mismatch: A=%d B=%d", len(gotA.PerSample), len(gotB.PerSample))
	}
	for i := range gotA.PerSample {
		if gotA.PerSample[i] != gotB.PerSample[i] {
			t.Fatalf("per-sample[%d] mismatch: A=%d B=%d", i, gotA.PerSample[i], gotB.PerSample[i])
		}
	}
}
