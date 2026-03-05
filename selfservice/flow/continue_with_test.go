// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirstContinueWithRedirect(t *testing.T) {
	t.Parallel()

	t.Run("skips redirect actions with empty URLs", func(t *testing.T) {
		t.Parallel()

		cwr, ok := FirstContinueWithRedirect([]ContinueWith{
			NewContinueWithVerificationUI(uuid.Must(uuid.NewV4()), "verified@example.com", ""),
			NewContinueWithRedirectBrowserTo(""),
			&ContinueWithSettingsUI{
				Action: ContinueWithActionShowSettingsUIString,
				Flow:   ContinueWithSettingsUIFlow{ID: uuid.Must(uuid.NewV4())},
			},
		})

		require.False(t, ok)
		assert.Nil(t, cwr)
	})

	t.Run("uses explicit redirect priority", func(t *testing.T) {
		t.Parallel()

		cwr, ok := FirstContinueWithRedirect([]ContinueWith{
			&ContinueWithSettingsUI{
				Action: ContinueWithActionShowSettingsUIString,
				Flow: ContinueWithSettingsUIFlow{
					ID:  uuid.Must(uuid.NewV4()),
					URL: "https://settings.example.test",
				},
			},
			NewContinueWithVerificationUI(uuid.Must(uuid.NewV4()), "verified@example.com", "https://verification.example.test"),
			NewContinueWithRedirectBrowserTo("https://return.example.test"),
		})

		require.True(t, ok)
		assert.Equal(t, string(ContinueWithActionRedirectBrowserToString), cwr.GetAction())
		assert.Equal(t, "https://return.example.test", cwr.RedirectUrl())
	})

	t.Run("falls back to show UI actions when no explicit redirect exists", func(t *testing.T) {
		t.Parallel()

		cwr, ok := FirstContinueWithRedirect([]ContinueWith{
			&ContinueWithSettingsUI{
				Action: ContinueWithActionShowSettingsUIString,
				Flow: ContinueWithSettingsUIFlow{
					ID:  uuid.Must(uuid.NewV4()),
					URL: "https://settings.example.test",
				},
			},
			NewContinueWithVerificationUI(uuid.Must(uuid.NewV4()), "verified@example.com", "https://verification.example.test"),
		})

		require.True(t, ok)
		assert.Equal(t, string(ContinueWithActionShowVerificationUIString), cwr.GetAction())
		assert.Equal(t, "https://verification.example.test", cwr.RedirectUrl())
	})
}
