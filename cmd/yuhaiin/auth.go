package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/managementauth"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Optional manual bootstrap/recovery requires local execution and access to the
// private identity database. Normal first-time setup uses the startup code.
// Passwords are supplied only to the password derivation client, never to this command.
func authCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: yuhaiin auth bootstrap -login <name> [-path <data-directory>] | auth recover -id <user-id> [-path <data-directory>]")
	}
	action := args[0]
	flags := flag.NewFlagSet("auth", flag.ContinueOnError)
	dir := flags.String("path", configuration.DataDir.Load(), "data directory")
	login := flags.String("login", "", "initial administrator login")
	id := flags.String("id", "", "user ID for local credential recovery")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || action != "bootstrap" && action != "recover" {
		return errors.New("invalid auth command")
	}
	ctx := context.Background()
	db, err := storagesqlite.OpenManagement(ctx, filepath.Join(*dir, "management.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	store := managementauth.NewStore(db.DB())
	if action == "bootstrap" {
		u, enrollment, err := store.CreateUser(ctx, "local", *login, managementauth.Admin, true)
		if err != nil {
			return err
		}
		return json.MarshalWrite(os.Stdout, struct {
			User       managementauth.User             `json:"user"`
			Enrollment managementauth.IssuedCredential `json:"enrollment"`
		}{u, enrollment})
	}
	if *id == "" {
		return errors.New("local recovery requires -id")
	}
	enrollment, err := store.ResetEnrollment(ctx, "local", *id)
	if err != nil {
		return err
	}
	return json.MarshalWrite(os.Stdout, enrollment)
}
