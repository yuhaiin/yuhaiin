package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type ProxyCredential struct {
	ID        string   `json:"id"`
	UserID    string   `json:"userId"`
	Name      string   `json:"name"`
	Inbounds  []string `json:"inbounds"`
	Protocols []string `json:"protocols"`
	CreatedAt int64    `json:"createdAt"`
	ExpiresAt int64    `json:"expiresAt"`
	Revoked   bool     `json:"revoked"`
}

type ProxyCredentialRequest struct {
	Owner     string   `json:"owner"`
	Name      string   `json:"name"`
	Inbounds  []string `json:"inbounds"`
	Protocols []string `json:"protocols"`
	ExpiresAt int64    `json:"expiresAt"`
}

type IssuedProxyCredential struct {
	ProxyCredential
	Secret string `json:"secret"`
}

type proxyRecord struct {
	ProxyCredential
	login          string
	groups         []string
	generation     int64
	identity       *proxyauth.Identity
	cancel         context.CancelFunc
	verifier, wire [32]byte
	ntHash         [16]byte
	hasNTHash      bool
}

// ProxyCredentials owns a bounded, revocable authentication snapshot. The hot
// path performs a hash lookup, never a KDF or database query. A periodic reload
// also observes local recovery commands executed by another process.
type ProxyCredentials struct {
	store            *Store
	mu               sync.RWMutex
	reloadMu         sync.Mutex
	records          map[string]*proxyRecord
	proofs           map[[32]byte]*proxyRecord
	memberships      map[string][]string
	appliedGroups    map[string]uint64
	nextGroups       map[string]uint64
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	observeFailure   func(string, string)
	resourceObserver func([]trafficcontrol.IdentityBinding) error
}

// SetFailureObserver is installed before listeners are created. It receives no
// submitted username, proof, verifier or other authentication material.
func (p *ProxyCredentials) SetFailureObserver(observe func(string, string)) {
	p.mu.Lock()
	p.observeFailure = observe
	p.mu.Unlock()
}

func NewProxyCredentials(ctx context.Context, store *Store) (*ProxyCredentials, error) {
	ctx, cancel := context.WithCancel(ctx)
	p := &ProxyCredentials{store: store, records: make(map[string]*proxyRecord), proofs: make(map[[32]byte]*proxyRecord), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	if err := p.Reload(); err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				p.clear()
				return
			case <-ticker.C:
				_ = p.Reload()
			}
		}
	}()
	return p, nil
}

func (p *ProxyCredentials) Close() error { p.cancel(); <-p.done; return nil }
func (p *ProxyCredentials) clear() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.records {
		r.cancel()
	}
	clear(p.records)
	clear(p.proofs)
	clear(p.memberships)
	clear(p.appliedGroups)
}

func (p *ProxyCredentials) Reload() error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	p.mu.Lock()
	next, proofs, err := p.prepareReloadLocked()
	observer := p.resourceObserver
	changed := err == nil && resourceBindingsChanged(p.records, next)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	// Existing unaffected credentials remain readable while resource compilation
	// and durable quota-state loads run. Changed identities are already canceled.
	if observer != nil && changed {
		err = observer(resourceBindings(next))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		// Unchanged identities still match the active resource snapshot.
		// Deny only new/changed memberships until preparation recovers.
		safe := make(map[string]*proxyRecord)
		safeProofs := make(map[[32]byte]*proxyRecord)
		for id, r := range next {
			old := p.records[id]
			if old != nil && old.UserID == r.UserID && slices.Equal(old.groups, r.groups) {
				safe[id] = r
				safeProofs[r.verifier] = r
				safeProofs[r.wire] = r
			} else {
				r.cancel()
				if old != nil {
					old.cancel()
				}
			}
		}
		p.records, p.proofs = safe, safeProofs
		clear(p.appliedGroups)
		return err
	}
	p.records, p.proofs = next, proofs
	p.appliedGroups = p.nextGroups
	return nil
}

// The caller holds mu and reloadMu; no resource callback runs under mu.
func (p *ProxyCredentials) prepareReloadLocked() (map[string]*proxyRecord, map[[32]byte]*proxyRecord, error) {
	// Fail closed if the private database becomes unreadable.
	next, err := p.load()
	if err != nil {
		for _, r := range p.records {
			r.cancel()
		}
		clear(p.records)
		clear(p.proofs)
		clear(p.memberships)
		clear(p.appliedGroups)
		return nil, nil, err
	}
	proofs := make(map[[32]byte]*proxyRecord, len(next)*2)
	for id, r := range next {
		old := p.records[id]
		if old != nil && old.generation == r.generation && slices.Equal(old.groups, r.groups) && old.identity.Valid() {
			r.identity, r.cancel = old.identity, old.cancel
		} else {
			var ctx context.Context
			if r.ExpiresAt != 0 {
				ctx, r.cancel = context.WithDeadline(p.ctx, time.Unix(r.ExpiresAt, 0))
			} else {
				ctx, r.cancel = context.WithCancel(p.ctx)
			}
			r.identity = &proxyauth.Identity{UserID: r.UserID, CredentialID: id, GroupIDs: r.groups, Context: ctx}
		}
		proofs[r.verifier] = r
		proofs[r.wire] = r
	}
	for id, old := range p.records {
		if r := next[id]; r == nil || r.identity != old.identity {
			old.cancel()
		}
	}
	return next, proofs, nil
}

func (p *ProxyCredentials) load() (map[string]*proxyRecord, error) {
	// One read transaction gives credentials and memberships a consistent view.
	// Intern memberships per owner and retain unchanged slices across reloads:
	// 64 device credentials must not copy the same group set 64 times per second.
	tx, err := p.store.db.BeginTx(p.ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	memberships, err := loadMemberships(p.ctx, tx)
	if err != nil {
		return nil, err
	}
	for user, groups := range memberships {
		if previous := p.memberships[user]; slices.Equal(previous, groups) {
			memberships[user] = previous
		}
	}
	rows, err := tx.QueryContext(p.ctx, `SELECT c.id,c.user_id,c.name,c.inbounds,c.protocols,c.created_at,c.expires_at,c.revoked,c.verifier,c.wire_verifier,c.sstp_nt_hash,c.generation,u.login
 FROM proxy_credentials c JOIN management_users u ON u.id=c.user_id
 WHERE c.revoked=0 AND u.disabled=0 AND c.generation=u.generation AND (c.expires_at=0 OR c.expires_at>?)`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]*proxyRecord)
	for rows.Next() {
		r := new(proxyRecord)
		var inbounds, protocols string
		var verifier, wire []byte
		var ntHash []byte
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &inbounds, &protocols, &r.CreatedAt, &r.ExpiresAt, &r.Revoked, &verifier, &wire, &ntHash, &r.generation, &r.login); err != nil {
			return nil, err
		}
		if len(verifier) != 32 || len(wire) != 32 {
			return nil, ErrInvalid
		}
		if err := json.Unmarshal([]byte(inbounds), &r.Inbounds); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(protocols), &r.Protocols); err != nil {
			return nil, err
		}
		copy(r.verifier[:], verifier)
		r.groups = memberships[r.UserID]
		copy(r.wire[:], wire)
		if len(ntHash) != 0 && len(ntHash) != 16 {
			return nil, ErrInvalid
		}
		if len(ntHash) == 16 {
			copy(r.ntHash[:], ntHash)
			r.hasNTHash = true
		}
		out[r.ID] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	groupRows, err := tx.QueryContext(p.ctx, `SELECT id,revision FROM traffic_groups`)
	if err != nil {
		return nil, err
	}
	groups := make(map[string]uint64)
	for groupRows.Next() {
		var id string
		var revision uint64
		if err = groupRows.Scan(&id, &revision); err != nil {
			_ = groupRows.Close()
			return nil, err
		}
		groups[id] = revision
	}
	if err = errors.Join(groupRows.Err(), groupRows.Close()); err != nil {
		return nil, err
	}
	p.nextGroups = groups
	p.memberships = memberships
	return out, nil
}

func loadMemberships(ctx context.Context, tx *sql.Tx) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT user_id,group_id FROM traffic_group_members ORDER BY user_id,group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]string)
	for rows.Next() {
		var user, group string
		if err := rows.Scan(&user, &group); err != nil {
			return nil, err
		}
		out[user] = append(out[user], group)
	}
	return out, rows.Err()
}

func (p *ProxyCredentials) Verifier(inboundID, protocol string, allowedUsers []string) proxyauth.Verifier {
	allowedUsers = slices.Clone(allowedUsers)
	verify := func(ctx context.Context, username string, proof []byte) (*proxyauth.Identity, error) {
		if ctx.Err() != nil {
			return nil, proxyauth.ErrUnauthorized
		}
		var key [32]byte
		if protocol == "yuubinsya" {
			if len(proof) != 32 {
				return nil, proxyauth.ErrUnauthorized
			}
			key = sha256.Sum256(proof)
		} else {
			key = sha256.Sum256(proof)
		}
		p.mu.RLock()
		defer p.mu.RUnlock()
		r := p.proofs[key]
		if r == nil || !r.identity.Valid() || !slices.Contains(allowedUsers, r.UserID) ||
			(len(r.Inbounds) > 0 && !slices.Contains(r.Inbounds, inboundID)) ||
			(len(r.Protocols) > 0 && !slices.Contains(r.Protocols, protocol)) ||
			((protocol == "http" || protocol == "socks5") && !strings.EqualFold(username, r.login)) {
			return nil, proxyauth.ErrUnauthorized
		}
		// Do not accept a wire verifier in a raw-secret protocol or vice versa.
		if (protocol == "yuubinsya" && key != r.wire) || (protocol != "yuubinsya" && key != r.verifier) {
			return nil, proxyauth.ErrUnauthorized
		}
		return r.identity, nil
	}
	p.mu.RLock()
	observe := p.observeFailure
	p.mu.RUnlock()
	if observe == nil {
		return verify
	}
	return func(ctx context.Context, username string, proof []byte) (*proxyauth.Identity, error) {
		identity, err := verify(ctx, username, proof)
		if err != nil && ctx.Err() == nil {
			observe(inboundID, protocol)
		}
		return identity, err
	}
}

// MSCHAPv2Verifier authenticates SSTP challenge responses using the existing
// revocable per-device secrets. Only newly issued or rotated credentials have
// NT-hash material; pre-migration credentials must be rotated for SSTP.
func (p *ProxyCredentials) MSCHAPv2Verifier(inboundID string, allowedUsers []string) proxyauth.MSCHAPv2Verifier {
	allowedUsers = slices.Clone(allowedUsers)
	return func(ctx context.Context, username string, challenge, peerChallenge [16]byte, response [24]byte) (*proxyauth.Identity, [16]byte, error) {
		if ctx.Err() != nil {
			return nil, [16]byte{}, proxyauth.ErrUnauthorized
		}
		p.mu.RLock()
		defer p.mu.RUnlock()
		for _, record := range p.records {
			if !record.hasNTHash || !record.identity.Valid() ||
				!strings.EqualFold(username, record.login) ||
				!slices.Contains(allowedUsers, record.UserID) ||
				(len(record.Inbounds) > 0 && !slices.Contains(record.Inbounds, inboundID)) ||
				(len(record.Protocols) > 0 && !slices.Contains(record.Protocols, "sstp")) {
				continue
			}
			expected := mschap.GenerateNTResponseFromHash(challenge, peerChallenge, username, record.ntHash)
			if subtle.ConstantTimeCompare(expected[:], response[:]) == 1 {
				return record.identity, record.ntHash, nil
			}
		}
		return nil, [16]byte{}, proxyauth.ErrUnauthorized
	}
}

func validateProxyRequest(r ProxyCredentialRequest) error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 || len(r.Inbounds) > 256 || len(r.Protocols) > 5 || r.ExpiresAt < 0 || (r.ExpiresAt != 0 && r.ExpiresAt <= time.Now().Unix()) {
		return ErrInvalid
	}
	for _, id := range r.Inbounds {
		if strings.TrimSpace(id) == "" || len(id) > 128 {
			return ErrInvalid
		}
	}
	for _, v := range r.Protocols {
		if !slices.Contains([]string{"http", "socks5", "yuubinsya", "hysteria2", "sstp"}, v) {
			return ErrInvalid
		}
	}
	return nil
}

func (p *ProxyCredentials) Issue(ctx context.Context, actor Principal, r ProxyCredentialRequest) (IssuedProxyCredential, error) {
	if !actor.Allows(ProxyCredentialsManage) && !actor.Allows(ProxyCredentialsOwn) {
		return IssuedProxyCredential{}, ErrForbidden
	}
	if r.Owner == "" {
		r.Owner = actor.UserID
	}
	if r.Owner != actor.UserID && !actor.Allows(ProxyCredentialsManage) {
		return IssuedProxyCredential{}, ErrForbidden
	}
	if err := validateProxyRequest(r); err != nil {
		return IssuedProxyCredential{}, err
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedProxyCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	issued, err := issueProxy(ctx, tx, r)
	if err != nil {
		return issued, err
	}
	if err = recordEvent(ctx, tx, "proxy-credential.created", actor.UserID, issued.ID); err != nil {
		return IssuedProxyCredential{}, err
	}
	if err = tx.Commit(); err != nil {
		return IssuedProxyCredential{}, err
	}
	return issued, p.Reload()
}

func issueProxy(ctx context.Context, tx *sql.Tx, r ProxyCredentialRequest) (IssuedProxyCredential, error) {
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM management_users WHERE id=? AND disabled=0`, r.Owner).Scan(&generation); err != nil {
		return IssuedProxyCredential{}, ErrInvalid
	}
	// Bound retained rows while allowing a revoked device slot to be reused.
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_credentials WHERE user_id=? AND (revoked=1 OR (expires_at>0 AND expires_at<=?) OR generation!=?)`, r.Owner, time.Now().Unix(), generation); err != nil {
		return IssuedProxyCredential{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM proxy_credentials WHERE user_id=?`, r.Owner).Scan(&count); err != nil {
		return IssuedProxyCredential{}, err
	}
	if count >= 64 {
		return IssuedProxyCredential{}, ErrConflict
	}
	var entropy [32]byte
	_, _ = rand.Read(entropy[:])
	secret := "yp_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	verifier := sha256.Sum256([]byte(secret))
	wireToken := sha256.Sum256([]byte(secret + "+s@1t"))
	wire := sha256.Sum256(wireToken[:])
	ntHash := mschap.NTPasswordHash(secret)
	inbounds, _ := json.Marshal(r.Inbounds)
	protocols, _ := json.Marshal(r.Protocols)
	c := ProxyCredential{ID: uuid.New().String(), UserID: r.Owner, Name: r.Name, Inbounds: slices.Clone(r.Inbounds), Protocols: slices.Clone(r.Protocols), CreatedAt: time.Now().Unix(), ExpiresAt: r.ExpiresAt}
	_, err := tx.ExecContext(ctx, `INSERT INTO proxy_credentials(id,user_id,name,verifier,wire_verifier,sstp_nt_hash,generation,inbounds,protocols,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, c.ID, c.UserID, c.Name, verifier[:], wire[:], ntHash[:], generation, string(inbounds), string(protocols), c.CreatedAt, c.ExpiresAt)
	return IssuedProxyCredential{ProxyCredential: c, Secret: secret}, err
}

func (p *ProxyCredentials) List(ctx context.Context, owner string) ([]ProxyCredential, error) {
	rows, err := p.store.db.QueryContext(ctx, `SELECT id,user_id,name,inbounds,protocols,created_at,expires_at,revoked FROM proxy_credentials WHERE user_id=? ORDER BY created_at,id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyCredential{}
	for rows.Next() {
		var c ProxyCredential
		var inbounds, protocols string
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &inbounds, &protocols, &c.CreatedAt, &c.ExpiresAt, &c.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(inbounds), &c.Inbounds); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(protocols), &c.Protocols); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *ProxyCredentials) Revoke(ctx context.Context, actor Principal, id string) error {
	if !actor.Allows(ProxyCredentialsManage) && !actor.Allows(ProxyCredentialsOwn) {
		return ErrForbidden
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE proxy_credentials SET revoked=1 WHERE id=? AND (user_id=? OR ?=1)`, id, actor.UserID, actor.Allows(ProxyCredentialsManage))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err = recordEvent(ctx, tx, "proxy-credential.revoked", actor.UserID, id); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return p.Reload()
}

// Delete removes the credential record and cancels any sessions using it.
func (p *ProxyCredentials) Delete(ctx context.Context, actor Principal, id string) error {
	if !actor.Allows(ProxyCredentialsManage) && !actor.Allows(ProxyCredentialsOwn) {
		return ErrForbidden
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM proxy_credentials WHERE id=? AND (user_id=? OR ?=1)`, id, actor.UserID, actor.Allows(ProxyCredentialsManage))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err = recordEvent(ctx, tx, "proxy-credential.deleted", actor.UserID, id); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return p.Reload()
}

func (p *ProxyCredentials) Rotate(ctx context.Context, actor Principal, id string) (IssuedProxyCredential, error) {
	if !actor.Allows(ProxyCredentialsManage) && !actor.Allows(ProxyCredentialsOwn) {
		return IssuedProxyCredential{}, ErrForbidden
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedProxyCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var r ProxyCredentialRequest
	var inbounds, protocols string
	err = tx.QueryRowContext(ctx, `SELECT c.user_id,c.name,c.inbounds,c.protocols,c.expires_at FROM proxy_credentials c JOIN management_users u ON u.id=c.user_id WHERE c.id=? AND c.revoked=0 AND u.disabled=0 AND c.generation=u.generation AND (c.expires_at=0 OR c.expires_at>?)`, id, time.Now().Unix()).Scan(&r.Owner, &r.Name, &inbounds, &protocols, &r.ExpiresAt)
	if err != nil {
		return IssuedProxyCredential{}, err
	}
	if r.Owner != actor.UserID && !actor.Allows(ProxyCredentialsManage) {
		return IssuedProxyCredential{}, ErrForbidden
	}
	if json.Unmarshal([]byte(inbounds), &r.Inbounds) != nil || json.Unmarshal([]byte(protocols), &r.Protocols) != nil {
		return IssuedProxyCredential{}, ErrInvalid
	}
	// Delete the replaced row inside the transaction so rotation works at the cap.
	if _, err = tx.ExecContext(ctx, `DELETE FROM proxy_credentials WHERE id=?`, id); err != nil {
		return IssuedProxyCredential{}, err
	}
	issued, err := issueProxy(ctx, tx, r)
	if err != nil {
		return IssuedProxyCredential{}, err
	}
	if err = recordEvent(ctx, tx, "proxy-credential.rotated", actor.UserID, id); err != nil {
		return IssuedProxyCredential{}, err
	}
	if err = tx.Commit(); err != nil {
		return IssuedProxyCredential{}, err
	}
	return issued, p.Reload()
}

var _ proxyauth.Provider = (*ProxyCredentials)(nil)

// GroupRevision reports a fully published identity generation, including group
// tombstones. A failed reload reports no applied revision rather than success.
func (p *ProxyCredentials) GroupRevision(id string) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.appliedGroups[id]
}
