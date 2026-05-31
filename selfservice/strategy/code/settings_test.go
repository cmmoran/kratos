// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
)

func TestCodeCredentialsFromVerifiedAddresses(t *testing.T) {
	t.Parallel()

	t.Run("creates first-class email and sms code credentials", func(t *testing.T) {
		t.Parallel()

		creds, err := (&Strategy{}).codeCredentialsFromVerifiedAddresses(&identity.Identity{
			VerifiableAddresses: []identity.VerifiableAddress{
				{Value: "User@Example.Com", Via: identity.AddressTypeEmail, Verified: true},
				{Value: "+14155550100", Via: identity.AddressTypeSMS, Verified: true},
				{Value: "unverified@example.com", Via: identity.AddressTypeEmail, Verified: false},
			},
		})
		require.NoError(t, err)
		require.Equal(t, identity.CredentialsTypeCodeAuth, creds.Type)
		require.ElementsMatch(t, []string{"user@example.com", "+14155550100"}, creds.Identifiers)

		var conf identity.CredentialsCode
		require.NoError(t, json.Unmarshal(creds.Config, &conf))
		require.False(t, conf.Disabled)
		require.ElementsMatch(t, []identity.CredentialsCodeAddress{
			{Channel: identity.CodeChannelEmail, Address: "user@example.com"},
			{Channel: identity.CodeChannelSMS, Address: "+14155550100"},
		}, conf.Addresses)
	})

	t.Run("requires a verified code-capable address", func(t *testing.T) {
		t.Parallel()

		_, err := (&Strategy{}).codeCredentialsFromVerifiedAddresses(&identity.Identity{
			VerifiableAddresses: []identity.VerifiableAddress{
				{Value: "unverified@example.com", Via: identity.AddressTypeEmail, Verified: false},
			},
		})
		require.Error(t, err)
	})
}
