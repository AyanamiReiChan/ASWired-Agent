package updater

import (
	"testing"
)

func TestAcknowledgementRequiresMatchingTaskAndVersion(t *testing.T) {
	dir := t.TempDir()
	state := State{TaskID: "upgrade", Status: "staged", Version: "1.2.3"}
	if err := write(dir, state); err != nil {
		t.Fatal(err)
	}
	if err := Acknowledge(dir, "other", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	actual, _ := read(dir)
	if actual.Status != "staged" {
		t.Fatal("unrelated acknowledgement promoted update")
	}
	if err := Acknowledge(dir, "upgrade", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	actual, _ = read(dir)
	if actual.Status != "ready" {
		t.Fatal("confirmed staging not marked ready")
	}
	actual.Status = "restarting"
	if err := write(dir, actual); err != nil {
		t.Fatal(err)
	}
	if err := Acknowledge(dir, "", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	actual, _ = read(dir)
	if actual.Status != "restarting" {
		t.Fatal("old version confirmed upgrade")
	}
	if err := Acknowledge(dir, "", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	actual, _ = read(dir)
	if actual.Status != "healthy" {
		t.Fatal("new authenticated version not confirmed")
	}
}
