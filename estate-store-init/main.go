// Store bootstrap for privileged setup; not a verifier or a migration tool.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	corimstore "github.com/veraison/corim-store/pkg/store"
	"github.com/veraison/services/policy"
	"go.uber.org/zap"
)

const producer = "veraison-services-6b37dd17e093cb9358743d76d8a3d5a254589e7c-store-init-v1"

type receipt struct {
	Subject  string `json:"subject"`
	Producer string `json:"producer"`
}

func regularPrivate(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() == 0 {
		return errors.New("store file is not private, regular and nonempty")
	}
	return nil
}

func policyStore(root string) (*policy.Store, error) {
	cfg := viper.New()
	cfg.Set("backend", "sql")
	cfg.Set("sql.driver", "sqlite3")
	cfg.Set("sql.datasource", filepath.Join(root, "policy.sql"))
	cfg.Set("sql.max_connections", 2)
	return policy.NewStore(cfg, zap.NewNop().Sugar())
}

func databases(root string, create bool) (result error) {
	en, err := corimstore.Open(context.Background(), corimstore.NewConfig("sqlite", filepath.Join(root, "endorsements.sql")))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, en.Close()) }()
	if create {
		if err := en.Init(); err != nil {
			return err
		}
	}
	if _, err := en.QueryManifestEntries(nil); err != nil && !errors.Is(err, corimstore.ErrNoMatch) {
		return err
	}
	po, err := policyStore(root)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, po.KVStore.Close()) }()
	if create {
		if err := po.Setup(); err != nil {
			return err
		}
	}
	_, err = po.KVStore.GetKeys()
	return err
}

func initialize(root, subject string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(subject) {
		return errors.New("requires absolute state directory and bound subject digest")
	}
	parent, err := os.Lstat(filepath.Dir(root))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return errors.New("state parent is not trusted")
	}
	st, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0700); err != nil {
			return err
		}
		st, err = os.Lstat(root)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("state directory is not private")
	}
	// The service owns this directory, not its root-owned /var/lib parent.
	lock := filepath.Join(root, ".init-lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		return errors.New("initialization locked; preserve and inspect existing state")
	}
	defer os.Remove(lock)
	expected := receipt{Subject: subject, Producer: producer}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != ".init-lock" {
		marker := filepath.Join(root, "initialized.json")
		for _, name := range []string{"initialized.json", "endorsements.sql", "policy.sql"} {
			if err := regularPrivate(filepath.Join(root, name)); err != nil {
				return err
			}
		}
		data, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		var actual receipt
		if err := json.Unmarshal(data, &actual); err != nil {
			return err
		}
		if actual != expected {
			return errors.New("existing state belongs to another subject or initializer")
		}
		// Only query existing schemas. Never reinitialize, migrate or erase them.
		return databases(root, false)
	}
	// Failure leaves unsealed state for diagnosis. It must not be retried as fresh.
	if err := databases(root, true); err != nil {
		return err
	}
	for _, name := range []string{"endorsements.sql", "policy.sql"} {
		if err := os.Chmod(filepath.Join(root, name), 0600); err != nil {
			return err
		}
	}
	data, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, "initialized.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: veraison-store-init ABSOLUTE_STATE_DIR SUBJECT_SHA256")
		os.Exit(2)
	}
	if err := initialize(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("STORE_READY")
}
