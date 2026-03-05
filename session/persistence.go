// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"time"

	"github.com/ory/pop/v6"

	"github.com/ory/kratos/identity"

	"github.com/ory/x/pagination/keysetpagination"

	"github.com/gofrs/uuid"
)

type PersistenceProvider interface {
	SessionPersister() Persister
}

type Persister interface {
	GetConnection(ctx context.Context) *pop.Connection

	// GetSession retrieves a session from the store.
	GetSession(ctx context.Context, sid uuid.UUID, expandables Expandables) (*Session, error)

	// ListSessions retrieves all sessions.
	ListSessions(ctx context.Context, active *bool, paginatorOpts []keysetpagination.Option, expandables Expandables) ([]Session, *keysetpagination.Paginator, error)

	// ListSessionsByIdentity retrieves sessions for an identity from the store.
	ListSessionsByIdentity(ctx context.Context, iID uuid.UUID, active *bool, page, perPage int, except uuid.UUID, expandables Expandables) ([]Session, int64, error)

	// UpsertSession inserts or updates a session into / in the store.
	UpsertSession(ctx context.Context, s *Session) error

	// ExtendSession updates the expiry of a session.
	ExtendSession(ctx context.Context, sessionID uuid.UUID) error

	// DeleteSession removes a session from the store.
	DeleteSession(ctx context.Context, id uuid.UUID) error

	// DeleteSessionsByIdentity removes all active session from the store for the given identity.
	DeleteSessionsByIdentity(ctx context.Context, identity uuid.UUID) error

	// GetSessionByToken gets the session associated with the given token.
	//
	// Functionality is similar to GetSession but accepts a session token
	// instead of a session ID.
	GetSessionByToken(ctx context.Context, token string, expandables Expandables, identityExpandables identity.Expandables) (*Session, error)

	// DeleteExpiredSessions deletes sessions that expired before the given time.
	DeleteExpiredSessions(context.Context, time.Time, int) error

	// DeleteSessionByToken deletes a session associated with the given token.
	//
	// Functionality is similar to DeleteSession but accepts a session token
	// instead of a session ID.
	DeleteSessionByToken(context.Context, string) error

	// RevokeSessionByToken marks a session inactive with the given token.
	RevokeSessionByToken(ctx context.Context, token string) error

	// RevokeSessionById marks a session inactive with the specified uuid
	RevokeSessionById(ctx context.Context, sID uuid.UUID) error

	// RevokeSession marks a given session inactive.
	RevokeSession(ctx context.Context, iID, sID uuid.UUID) error

	// RevokeSessionsIdentityExcept marks all except the given session of an identity inactive. It returns the number of sessions that were revoked.
	RevokeSessionsIdentityExcept(ctx context.Context, iID, sID uuid.UUID) (int, error)

	// RevokeSessionsByIdentities marks all active sessions inactive for the given identity IDs. Returns the number of rows updated.
	RevokeSessionsByIdentities(ctx context.Context, identityIDs []uuid.UUID) (int, error)

	// RevokeSessionsByIDs marks the listed sessions inactive (only ones currently active). Returns the number of rows updated.
	RevokeSessionsByIDs(ctx context.Context, sessionIDs []uuid.UUID) (int, error)

	// RevokeAllSessions deactivates up to `limit` currently-active sessions
	// in the caller's network in a single SQL statement and returns the
	// number of rows actually updated (in the range [0, limit]).
	// Already-inactive sessions are skipped. A returned count below `limit`
	// signals that no more matching rows remain.
	RevokeAllSessions(ctx context.Context, limit int) (int, error)

	// DeleteSessionsByIdentities permanently deletes all sessions belonging to the given identity IDs. Returns the number of rows deleted.
	DeleteSessionsByIdentities(ctx context.Context, identityIDs []uuid.UUID) (int, error)

	// DeleteSessionsByIDs permanently deletes the listed sessions. Returns the number of rows deleted.
	DeleteSessionsByIDs(ctx context.Context, sessionIDs []uuid.UUID) (int, error)

	// DeleteAllSessions permanently deletes up to `limit` sessions in the
	// caller's network in a single SQL statement and returns the number of
	// rows actually deleted (in the range [0, limit]). A returned count
	// below `limit` signals that no more matching rows remain.
	DeleteAllSessions(ctx context.Context, limit int) (int, error)

	DevicePersister
}

type DevicePersister interface {
	CreateDevice(ctx context.Context, d *Device) error
	UpsertDevice(ctx context.Context, d *Device) error
	ListTrustedDevicesByIdentity(ctx context.Context, iID uuid.UUID) ([]Device, error)
	ListTrustedDevicesByIdentityWithExpiration(ctx context.Context, iID uuid.UUID, deviceTrustDuration time.Duration) ([]Device, error)
}
