// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/node"
)

func NewTrustedDevicesCodeNode(devices []session.Device) *node.Node {
	dataMap := make(map[string]string)
	if len(devices) > 0 {
		for _, d := range devices {
			if d.Trusted && d.DeviceTrustedFor(identity.CredentialsTypeCodeAuth) {
				devMap := make(map[string]string)
				if d.IPAddress != nil {
					devMap["ip_address"] = *d.IPAddress
				}
				if d.UserAgent != nil {
					devMap["user_agent"] = *d.UserAgent
				}
				if !d.CreatedAt.IsZero() {
					devMap["created_at"] = d.CreatedAt.UTC().Format(time.RFC3339Nano)
				}
				if d.Location != nil {
					devMap["location"] = *d.Location
				}
				if d.Fingerprint != nil {
					devMap["fingerprint"] = *d.Fingerprint
				}
				if len(devMap) > 0 {
					jsb, _ := json.Marshal(devMap)
					dataMap[d.ID.String()] = string(jsb)
				}
			}
		}
	}
	var respNode *node.Node
	if len(dataMap) > 0 {
		respNode = node.NewDivisionField(
			"code-trusted-devices",
			node.CodeGroup,
			node.WithDivisionAttributes(func(o *node.DivisionAttributes) {
				o.Data = dataMap
			}),
		)
	}

	return respNode
}

func sortNodes(ctx context.Context, n node.Nodes) error {
	return n.SortBySchema(ctx,
		node.SortUseOrder([]string{
			"csrf_token",
			"identifier",
			"code",
			"trust_device",
		}),
		node.SortUseOrderAppend([]string{
			"method",
			"resend",
			"email",
			"sms",
		}))
}
