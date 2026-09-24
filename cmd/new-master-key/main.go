// Command new-master-key creates a master key for natrium-recovery-server and has the STACKIT KMS encrypt it. It
// prints only the entry for NATRIUM_RECOVERY_MASTER_KEYS, <keyVersion>:<kmsVersion>:<base64 ciphertext>, after
// checking that the KMS decrypts it again. The master key in plaintext never leaves the process's memory.
//
// The KMS key and the service account come from the NATRIUM_RECOVERY_KMS_* variables of the server. The service
// account needs to encrypt and decrypt with the key.
//
//	new-master-key -key-version 2 -kms-version 1
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/config"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey"
)

func main() {
	err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, stackitFromEnvironment)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case err != nil:
		fmt.Fprintln(os.Stderr, "new-master-key:", err)
		os.Exit(1)
	}
}

func stackitFromEnvironment() (masterkey.KMS, error) {
	cfg, err := config.LoadKMS()
	if err != nil {
		return nil, err
	}
	return masterkey.NewStackit(cfg)
}

// run parses args, creates the master key with the KMS from newKMS and writes the entry to out. Usage goes to errOut.
func run(ctx context.Context, args []string, out, errOut io.Writer, newKMS func() (masterkey.KMS, error)) error {
	flags := flag.NewFlagSet("new-master-key", flag.ContinueOnError)
	flags.SetOutput(errOut)
	keyVersion := flags.Uint("key-version", 0, "version of the new master key, as key files name it (required, from 1)")
	kmsVersion := flags.Int64("kms-version", 0, "version of the KMS key to encrypt with (required, from 1)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case flags.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	case *keyVersion < 1 || *keyVersion > 1<<32-1:
		return errors.New("-key-version must be a version from 1")
	case *kmsVersion < 1:
		return errors.New("-kms-version must be a version from 1")
	}

	kms, err := newKMS()
	if err != nil {
		return err
	}
	entry, err := masterkey.Generate(ctx, kms, uint32(*keyVersion), *kmsVersion)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, entry.String())
	return err
}
