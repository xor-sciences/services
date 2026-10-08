package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializePreservesPopulatedMatchingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	subject := strings.Repeat("a", 64)
	if err := initialize(root, subject); err != nil {
		t.Fatal(err)
	}
	po, err := policyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := po.KVStore.Set("ordinary-control", `{"value":"preserve"}`); err != nil {
		t.Fatal(err)
	}
	if err := po.KVStore.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "policy.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if err := initialize(root, subject); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, "policy.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("reinitialization changed existing database")
	}
	if err := initialize(root, strings.Repeat("b", 64)); err == nil {
		t.Fatal("mismatched subject accepted")
	}
	after, err = os.ReadFile(filepath.Join(root, "policy.sql"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal changed existing state")
	}
}

func TestInitializePrecreatedPrivateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	subject := strings.Repeat("a", 64)
	if err := initialize(root, subject); err != nil {
		t.Fatal(err)
	}
	if err := initialize(root, subject); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".init-lock")); !os.IsNotExist(err) {
		t.Fatal("initializer lock was not removed")
	}
}

func TestRefuseIncompleteCorruptAndLinkedState(t *testing.T) {
	for _, mutation := range []string{"incomplete", "corrupt", "symlink", "locked"} {
		t.Run(mutation, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			subject := strings.Repeat("a", 64)
			if err := initialize(root, subject); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "endorsements.sql")
			switch mutation {
			case "incomplete":
				if err := os.Remove(filepath.Join(root, "initialized.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(target, []byte("not a database"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(target, target+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+".retained", target); err != nil {
					t.Fatal(err)
				}
			case "locked":
				if err := os.Mkdir(filepath.Join(root, ".init-lock"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := initialize(root, subject); err == nil {
				t.Fatal("unsafe existing state accepted")
			}
		})
	}
}
