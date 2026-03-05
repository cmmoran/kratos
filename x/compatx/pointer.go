// Copyright © 2026
// SPDX-License-Identifier: Apache-2.0

package compatx

// Ptr returns a pointer to v without relying on external helper APIs.
func Ptr[T any](v T) *T {
	return &v
}
