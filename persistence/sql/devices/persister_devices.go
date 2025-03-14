// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package devices

import (
	"context"
	"slices"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"

	"github.com/ory/kratos/session"
	"github.com/ory/x/contextx"
	"github.com/ory/x/popx"
	"github.com/ory/x/sqlcon"
)

var _ session.DevicePersister = (*DevicePersister)(nil)

type DevicePersister struct {
	ctxer contextx.Provider
	c     *pop.Connection
	nid   uuid.UUID
}

func NewPersister(r contextx.Provider, c *pop.Connection) *DevicePersister {
	return &DevicePersister{
		ctxer: r,
		c:     c,
	}
}

func (p *DevicePersister) NetworkID(ctx context.Context) uuid.UUID {
	return p.ctxer.Contextualizer().Network(ctx, p.nid)
}

func (p DevicePersister) WithNetworkID(nid uuid.UUID) session.DevicePersister {
	p.nid = nid
	return &p
}

func (p *DevicePersister) CreateDevice(ctx context.Context, d *session.Device) error {
	d.NID = p.NetworkID(ctx)
	return sqlcon.HandleError(popx.GetConnection(ctx, p.c.WithContext(ctx)).Create(d))
}

func (p *DevicePersister) UpsertDevice(ctx context.Context, d *session.Device) error {
	d.NID = p.NetworkID(ctx)
	q := popx.GetConnection(ctx, p.c.WithContext(ctx))

	currentDevice := new(session.Device)

	if d.ID.IsNil() {
		if !d.SessionID.IsNil() {
			if err := q.Q().Where("session_id = ? AND nid = ?", d.SessionID, d.NID).First(currentDevice); err != nil {
				return sqlcon.HandleError(err)
			}
			d.ID = currentDevice.ID
		}
	}

	if d.ID.IsNil() {
		return sqlcon.HandleError(q.Create(d))
	} else {
		return sqlcon.HandleError(q.UpdateColumns(d, "trusted", "authentication_methods"))
	}
}

func (p *DevicePersister) ListTrustedDevicesByIdentity(ctx context.Context, iID uuid.UUID) ([]session.Device, error) {
	nid := p.NetworkID(ctx)

	std := make([]session.Device, 0)
	q := popx.GetConnection(ctx, p.c.WithContext(ctx)).Q()
	if err := q.Where("session_id IN (select id from sessions where identity_id = ?) AND nid = ? AND trusted = true AND fingerprint IS NOT NULL", iID, nid).All(&std); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return std, nil
}

func (p *DevicePersister) ListTrustedDevicesByIdentityWithExpiration(ctx context.Context, iID uuid.UUID, deviceTrustDuration time.Duration) (devices []session.Device, err error) {
	devices, err = p.ListTrustedDevicesByIdentity(ctx, iID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	slices.DeleteFunc(devices, func(device session.Device) bool {
		if device.Trusted && len(device.AMR) > 0 {
			for _, amr := range device.AMR {
				if now.After(amr.CompletedAt.Add(deviceTrustDuration)) {
					return true
				}
			}
			return false
		}
		return true
	})

	return devices, nil
}
