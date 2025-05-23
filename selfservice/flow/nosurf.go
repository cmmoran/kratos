// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net/http"

	"github.com/ory/kratos/x/nosurfx"
)

func GetCSRFToken(reg interface {
	nosurfx.CSRFProvider
	nosurfx.CSRFTokenGeneratorProvider
}, w http.ResponseWriter, r *http.Request, p Type) string {
	token := reg.GenerateCSRFToken(r)
	if p != TypeBrowser {
		return token
	}

	if token == "" {
		return reg.CSRFHandler().RegenerateToken(w, r)
	}

	return token
}
