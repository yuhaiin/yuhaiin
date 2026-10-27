package archive

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"filippo.io/age"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
)

const (
	RecoveryFormat   = "yuhaiin-recovery"
	RecoveryVersion  = 2
	MaxFiles         = 4096
	MaxManifestBytes = 1 << 20
	MaxDataBytes     = contractrecovery.MaxDataBytes
	// age's 64 KiB authenticated chunks add 16 bytes each plus a small header.
	maxRecoveryEncryptedBytes = MaxDataBytes + (64 << 20)
	recoveryMagic             = "YUHAIIN-RECOVERY\x00\x01"
)

var ErrInvalid = errors.New("invalid, incomplete or unauthenticated recovery archive")

// Encryption is transient input, never a persisted settings document.
// Specify exactly one passphrase or external X25519 public recipient. Scheduled
// backups need only the public recipient; its private identity stays elsewhere.
type Encryption struct{ Passphrase, Recipient string }
type Decryption struct{ Passphrase, Identity string }

func (k Encryption) Validate() error { _, err := k.recipient(); return err }

func (k Encryption) recipient() (age.Recipient, error) {
	if (k.Passphrase == "") == (k.Recipient == "") || len(k.Passphrase) > 1024 || len(k.Recipient) > 1024 {
		return nil, errors.New("specify one backup passphrase or X25519 recipient")
	}
	if k.Passphrase != "" {
		return age.NewScryptRecipient(k.Passphrase)
	}
	recipient, err := age.ParseX25519Recipient(k.Recipient)
	if err != nil {
		return nil, errors.New("invalid external backup recipient")
	}
	return recipient, nil
}
func (k Decryption) identity() (age.Identity, error) {
	if (k.Passphrase == "") == (k.Identity == "") || len(k.Passphrase) > 1024 || len(k.Identity) > 1024 {
		return nil, errors.New("specify one backup passphrase or X25519 identity")
	}
	if k.Passphrase != "" {
		identity, err := age.NewScryptIdentity(k.Passphrase)
		if err != nil {
			return nil, errors.New("invalid backup passphrase")
		}
		// The writer uses age's default 18. Reject hostile KDF costs before work.
		identity.SetMaxWorkFactor(18)
		return identity, nil
	}
	identity, err := age.ParseX25519Identity(k.Identity)
	if err != nil {
		return nil, errors.New("invalid external backup identity")
	}
	return identity, nil
}

// Write writes an encrypted, uncompressed, versioned archive.
// The source must be a private immutable snapshot set, produced while its
// owners are coordinated/stopped. This function does not assert that separate
// live database snapshots are globally atomic. It neither closes dst nor
// publishes a partial output; callers must remove failed output.
func Write(ctx context.Context, dst io.Writer, sourceDirectory string, manifest contractrecovery.Manifest, key Encryption) (contractrecovery.Manifest, error) {
	recipient, err := key.recipient()
	if err != nil {
		return manifest, err
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	manifest.Format, manifest.Version = RecoveryFormat, RecoveryVersion
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxFiles {
		return manifest, errors.New("invalid recovery file count")
	}
	manifest.Files = slices.Clone(manifest.Files)
	root, err := os.OpenRoot(sourceDirectory)
	if err != nil {
		return manifest, err
	}
	defer root.Close()
	var total int64
	// Fill digests from real files, never caller-supplied lengths/checksums.
	for i := range manifest.Files {
		file := &manifest.Files[i]
		if err := validateRecoveryPath(file.Path); err != nil {
			return manifest, err
		}
		in, err := openRecoverySource(root, file.Path)
		if err != nil {
			return manifest, err
		}
		info, err := in.Stat()
		if err != nil {
			_ = in.Close()
			return manifest, err
		}
		if info.Size() < 0 || info.Size() > MaxDataBytes-total {
			_ = in.Close()
			return manifest, errors.New("recovery source exceeds size limit")
		}
		total += info.Size()
		hash := sha256.New()
		n, err := copyRecovery(ctx, hash, in, info.Size())
		closeErr := in.Close()
		if err != nil {
			return manifest, err
		}
		if closeErr != nil {
			return manifest, closeErr
		}
		file.Size, file.SHA256 = n, hex.EncodeToString(hash.Sum(nil))
	}
	if err := ValidateManifest(manifest); err != nil {
		return manifest, err
	}
	if err := inspectRecoveryDatabases(ctx, sourceDirectory, manifest); err != nil {
		return manifest, err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return manifest, err
	}
	if len(data) > MaxManifestBytes {
		return manifest, errors.New("recovery manifest exceeds 1 MiB")
	}
	encrypted, err := age.Encrypt(dst, recipient)
	if err != nil {
		return manifest, err
	}
	// Explicit lengths replace tar/zip headers, links and decompression. Manifest
	// bounds are checked before allocating or creating any restored file.
	if _, err := io.WriteString(encrypted, recoveryMagic); err != nil {
		return manifest, err
	}
	if err := binary.Write(encrypted, binary.BigEndian, uint32(len(data))); err != nil {
		return manifest, err
	}
	if _, err := encrypted.Write(data); err != nil {
		return manifest, err
	}
	for _, file := range manifest.Files {
		in, err := openRecoverySource(root, file.Path)
		if err != nil {
			return manifest, err
		}
		info, err := in.Stat()
		if err != nil {
			_ = in.Close()
			return manifest, err
		}
		if info.Size() != file.Size {
			_ = in.Close()
			return manifest, errors.New("recovery source changed during archive creation")
		}
		hash := sha256.New()
		_, err = copyRecovery(ctx, io.MultiWriter(encrypted, hash), in, file.Size)
		if err == nil {
			after, statErr := in.Stat()
			if statErr != nil {
				err = statErr
			} else if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
				err = errors.New("recovery source changed during archive creation")
			}
		}
		closeErr := in.Close()
		if err != nil {
			return manifest, err
		}
		if closeErr != nil {
			return manifest, closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return manifest, errors.New("recovery source changed during archive creation")
		}
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	if err := encrypted.Close(); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func openRecoverySource(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("recovery sources must be regular files")
	}
	file, err := root.Open(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("recovery source changed while opening")
	}
	return file, nil
}

// WriteFile atomically publishes a private archive without
// overwriting an existing backup. The temporary file is removed on every error.
func WriteFile(ctx context.Context, destination, sourceDirectory string, manifest contractrecovery.Manifest, key Encryption) (contractrecovery.Manifest, error) {
	written := manifest
	err := publishRecoveryFile(ctx, destination, func(output *os.File) error {
		var err error
		written, err = Write(ctx, output, sourceDirectory, manifest, key)
		return err
	})
	return written, err
}

// GenerateIdentityFile stores a newly generated external private key
// privately and exclusively. Only its public recipient is returned to callers.
func GenerateIdentityFile(ctx context.Context, destination string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	if err := publishRecoveryFile(ctx, destination, func(output *os.File) error {
		_, err := io.WriteString(output, identity.String()+"\n")
		return err
	}); err != nil {
		return "", err
	}
	return identity.Recipient().String(), nil
}

func publishRecoveryFile(ctx context.Context, destination string, write func(*os.File) error) error {
	output, err := os.CreateTemp(filepath.Dir(destination), ".recovery-write-*")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer os.Remove(temporary)
	if err := write(output); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(temporary, destination); err != nil {
		return fmt.Errorf("publish private recovery file without replacement: %w", err)
	}
	// File contents are synced before linking. Persist the directory entry on
	// platforms that support it before a caller records successful publication.
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(destination))
		if err != nil {
			return err
		}
		defer directory.Close()
		if err := directory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// Prepared owns an isolated private staging directory. No deployment
// files or live database connections are changed by Prepare.
// Close must run when preview/verification ends or ownership is transferred.
type Prepared struct {
	Manifest  contractrecovery.Manifest
	directory string
}

func (p *Prepared) Directory() string { return p.directory }
func (p *Prepared) Close() error      { return os.RemoveAll(p.directory) }

func Prepare(ctx context.Context, src io.Reader, stagingParent string, key Decryption) (*Prepared, error) {
	return PrepareWithSpaceCheck(ctx, src, stagingParent, key, nil)
}

// PrepareWithSpaceCheck uses the same authenticated decoder and
// checks the validated plaintext inventory before creating staging files.
func PrepareWithSpaceCheck(ctx context.Context, src io.Reader, stagingParent string, key Decryption, checkSpace func(int64) error) (_ *Prepared, resultErr error) {
	identity, err := key.identity()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A bounded encrypted reader protects against endless/unbounded input. Reads
	// and writes honor cancellation; KDF work is separately capped at age logN=18.
	limited := &io.LimitedReader{R: &recoveryContextReader{ctx, src}, N: maxRecoveryEncryptedBytes + 1}
	decrypted, err := age.Decrypt(limited, identity)
	if err != nil {
		return nil, recoveryReadError(ctx, err)
	}
	magic := make([]byte, len(recoveryMagic))
	if _, err := io.ReadFull(decrypted, magic); err != nil || string(magic) != recoveryMagic {
		return nil, recoveryReadError(ctx, err)
	}
	var size uint32
	if err := binary.Read(decrypted, binary.BigEndian, &size); err != nil {
		return nil, recoveryReadError(ctx, err)
	}
	if size == 0 || size > MaxManifestBytes {
		return nil, ErrInvalid
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(decrypted, data); err != nil {
		return nil, recoveryReadError(ctx, err)
	}
	var manifest contractrecovery.Manifest
	if err := json.Unmarshal(data, &manifest, json.RejectUnknownMembers(true)); err != nil {
		return nil, ErrInvalid
	}
	if err := ValidateManifest(manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if checkSpace != nil {
		var total int64
		for _, file := range manifest.Files {
			total += file.Size
		}
		if err := checkSpace(total); err != nil {
			return nil, err
		}
	}
	directory, err := os.MkdirTemp(stagingParent, ".recovery-stage-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for _, file := range manifest.Files {
		name := filepath.FromSlash(file.Path)
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return nil, err
		}
		output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		_, err = copyRecovery(ctx, io.MultiWriter(output, hash), decrypted, file.Size)
		if err == nil && hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			err = ErrInvalid
		}
		if err == nil {
			err = output.Sync()
		}
		closeErr := output.Close()
		if err != nil {
			return nil, recoveryReadError(ctx, err)
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	// Reading past the final content byte is mandatory: age's final AEAD chunk
	// must authenticate. A valid prefix, missing final tag or trailing plaintext
	// can never be returned as a successful preview/restoration candidate.
	var extra [1]byte
	n, err := io.ReadFull(decrypted, extra[:])
	if n != 0 || !errors.Is(err, io.EOF) || limited.N <= 0 {
		return nil, recoveryReadError(ctx, err)
	}
	if err := inspectRecoveryDatabases(ctx, directory, manifest); err != nil {
		return nil, err
	}
	return &Prepared{Manifest: manifest, directory: directory}, nil
}

func recoveryReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// Never include key parser input, encrypted headers or decrypted file bytes.
	return ErrInvalid
}

type recoveryContextReader struct {
	ctx context.Context
	io.Reader
}

func (r *recoveryContextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(data)
}
func copyRecovery(ctx context.Context, dst io.Writer, src io.Reader, size int64) (int64, error) {
	n, err := io.CopyBuffer(dst, io.LimitReader(&recoveryContextReader{ctx, src}, size), make([]byte, 32<<10))
	if err != nil {
		return n, err
	}
	if n != size {
		return n, io.ErrUnexpectedEOF
	}
	return n, ctx.Err()
}
