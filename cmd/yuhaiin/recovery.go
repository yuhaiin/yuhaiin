package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func recoveryCommand(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return executeRecoveryCommand(ctx, args, os.Stdout)
}

// Verification is usable even when the server cannot open its databases. It
// never starts listeners, opens deployment databases or replaces instance data.
func executeRecoveryCommand(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yuhaiin recovery keygen -identity-file FILE | recovery verify -archive FILE (-identity-file FILE | -passphrase-file FILE)")
	}
	action := args[0]
	flags := flag.NewFlagSet("recovery", flag.ContinueOnError)
	archive := flags.String("archive", "", "encrypted recovery archive")
	identityFile := flags.String("identity-file", "", "private X25519 identity file; newly created for keygen")
	passphraseFile := flags.String("passphrase-file", "", "private file containing the recovery passphrase")
	stagingParent := flags.String("staging-parent", os.TempDir(), "parent for temporary private verification staging")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected recovery arguments")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch action {
	case "keygen":
		if *identityFile == "" || *archive != "" || *passphraseFile != "" {
			return errors.New("keygen requires only -identity-file")
		}
		recipient, err := store.GenerateRecoveryIdentityFile(ctx, *identityFile)
		if err != nil {
			return err
		}
		return json.MarshalWrite(output, struct {
			Recipient string `json:"recipient"`
		}{recipient})
	case "verify":
		if *archive == "" || (*identityFile == "") == (*passphraseFile == "") {
			return errors.New("verify requires -archive and one private key/passphrase file")
		}
		var key store.RecoveryDecryption
		if *identityFile != "" {
			value, err := readRecoverySecretFile(*identityFile)
			if err != nil {
				return err
			}
			key.Identity = value
		} else {
			value, err := readRecoverySecretFile(*passphraseFile)
			if err != nil {
				return err
			}
			key.Passphrase = value
		}
		source, err := os.Open(*archive)
		if err != nil {
			return err
		}
		defer source.Close()
		prepared, err := store.PrepareRecoveryArchive(ctx, source, *stagingParent, key)
		if err != nil {
			return err
		}
		defer prepared.Close()
		return json.MarshalWrite(output, prepared.Manifest)
	default:
		return errors.New("unknown recovery action; use keygen or verify")
	}
}

func readRecoverySecretFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1025 {
		return "", errors.New("backup key/passphrase must be a regular file of at most 1025 bytes")
	}
	// Opening the file is the OS authorization check. Enforce private Unix
	// permissions; Windows access is governed by its existing account ACLs.
	if info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return "", errors.New("backup key/passphrase file must have owner-only permissions (0600)")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1026))
	if err != nil {
		return "", err
	}
	if len(data) > 1025 {
		return "", errors.New("backup key/passphrase file exceeds limit")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" || len(value) > 1024 {
		return "", errors.New("empty or overlong backup key/passphrase")
	}
	return value, nil
}
