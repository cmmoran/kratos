// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"encoding/json"
	"time"

	"github.com/pquerna/otp"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"

	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
)

func NewVerifyTOTPNode() *node.Node {
	return node.NewInputField(node.TOTPCode, nil, node.TOTPGroup,
		node.InputAttributeTypeText,
		node.WithRequiredInputAttribute).
		WithMetaLabel(text.NewInfoNodeLabelVerifyOTP())
}

func NewTOTPImageQRNode(key *otp.Key) (*node.Node, error) {
	src, err := KeyToHTMLImage(key)
	if err != nil {
		return nil, err
	}

	return node.NewImageField(node.TOTPQR, src, node.TOTPGroup, node.WithImageAttributes(func(a *node.ImageAttributes) {
		a.Height = 256
		a.Width = 256
	})).WithMetaLabel(text.NewInfoSelfServiceSettingsTOTPQRCode()), nil
}

func NewTOTPSourceURLNode(key *otp.Key) *node.Node {
	return node.NewTextField(node.TOTPSecretKey,
		text.NewInfoSelfServiceSettingsTOTPSecret(key.Secret()), node.TOTPGroup).
		WithMetaLabel(text.NewInfoSelfServiceSettingsTOTPSecretLabel())
}

func NewTrustedDevicesTOTPNode(devices []session.Device) *node.Node {
	dataMap := make(map[string]string)
	if len(devices) > 0 {
		for _, d := range devices {
			if d.Trusted && d.DeviceTrustedFor(identity.CredentialsTypeTOTP) {
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
			"totp-trusted-devices",
			node.TOTPGroup,
			node.WithDivisionAttributes(func(o *node.DivisionAttributes) {
				o.Data = dataMap
				return
			}),
		)
	}

	return respNode
}

func NewUnlinkTOTPNode() *node.Node {
	return node.NewInputField(node.TOTPUnlink, "true", node.TOTPGroup,
		node.InputAttributeTypeSubmit,
		node.WithRequiredInputAttribute).
		WithMetaLabel(text.NewInfoSelfServiceSettingsUpdateUnlinkTOTP())
}
