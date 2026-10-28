package certificates

import (
	"context"
	"errors"
)

type Account struct {
	Key Secret
	URI string
}

// AccountKey installs a newly generated key only if the CA/email account has no
// key. Concurrent issuers always receive the winning durable key, never their
// losing candidate. No network registration precedes this durable commit.
func (s *Store) AccountKey(ctx context.Context, directory, email string, candidate Secret) (Account, error) {
	if directory == "" || email == "" || len(directory) > 2048 || len(email) > 254 {
		return Account{}, errors.New("invalid ACME account identity")
	}
	if !candidate.Empty() {
		if len(candidate.value) > 32<<10 {
			return Account{}, errors.New("account key exceeds limit")
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO certificate_acme_accounts(directory,email,private_key_pem) VALUES(?,?,?) ON CONFLICT(directory,email) DO NOTHING`, directory, email, candidate.value); err != nil {
			return Account{}, err
		}
	}
	var account Account
	var key []byte
	err := s.db.QueryRowContext(ctx, `SELECT private_key_pem,account_uri FROM certificate_acme_accounts WHERE directory=? AND email=?`, directory, email).Scan(&key, &account.URI)
	account.Key = NewSecret(key)
	return account, err
}

func (s *Store) BindAccount(ctx context.Context, directory, email string, key Secret, uri string) error {
	if len(uri) == 0 || len(uri) > 2048 {
		return errors.New("invalid ACME account URI")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE certificate_acme_accounts SET account_uri=? WHERE directory=? AND email=? AND private_key_pem=? AND (account_uri='' OR account_uri=?)`, uri, directory, email, key.value, uri)
	return changed(result, err)
}
