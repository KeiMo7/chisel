package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/jpillora/chisel/share/settings"
)

// hashpwOptions implements `chisel hashpw`: it hashes a single password read
// from stdin (or a file) and prints the self-describing bcrypt hash, ready
// to paste into an authfile key. The password is never accepted as a
// command-line argument, so it does not appear in the process argument list.
type hashpwOptions struct {
	Cost int    `opts:"name=cost,short=-" help:"Bcrypt cost parameter (4..31). Defaults to 10. The chosen cost is embedded in the output hash, so verification stays correct if this default changes later."`
	File string `opts:"name=file,short=-" help:"Read the password from this file instead of stdin. Use - for explicit stdin (the default). A trailing newline is stripped."`
}

func (o *hashpwOptions) Run() error {
	var raw []byte
	var err error
	if o.File == "" || o.File == "-" {
		reader := bufio.NewReader(os.Stdin)
		raw, err = reader.ReadBytes('\n')
		if err != nil && len(raw) == 0 {
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
	} else {
		raw, err = os.ReadFile(o.File)
		if err != nil {
			return fmt.Errorf("failed to read password file: %w", err)
		}
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if password == "" {
		return fmt.Errorf("refusing to hash an empty password")
	}
	hash, err := settings.HashPassword(password, o.Cost)
	if err != nil {
		return err
	}
	// The hash is not a secret equivalent of the password, but it should
	// still be redirected into a file by the operator; print only the hash.
	fmt.Println(hash)
	return nil
}

// migrateAuthfileOptions implements `chisel migrate-authfile`: the
// validate-then-replace batch migration path for existing plaintext
// authfiles. The original bytes are retained as a timestamped backup.
type migrateAuthfileOptions struct {
	Path string `opts:"mode=arg" help:"Path to the users.json authfile to migrate in place."`
	Cost int    `opts:"name=cost,short=-" help:"Bcrypt cost parameter (4..31) applied to migrated entries. Defaults to 10."`
}

func (o *migrateAuthfileOptions) Run() error {
	if o.Path == "" {
		return fmt.Errorf("an authfile path is required")
	}
	report, err := settings.MigrateAuthFile(o.Path, o.Cost, os.Stdout)
	if err != nil {
		return err
	}
	if report.Migrated == 0 {
		fmt.Println("no plaintext entries found; file left unchanged")
	}
	return nil
}
