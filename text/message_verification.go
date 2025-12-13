// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"fmt"
	"time"
)

func NewErrorValidationVerificationFlowExpired(expiredAt time.Time) *Message {
	return &Message{
		ID:   ErrorValidationVerificationFlowExpired,
		Text: fmt.Sprintf("The verification flow expired %.2f minutes ago, please try again.", Since(expiredAt).Minutes()),
		Type: Error,
		Context: context(map[string]any{
			"expired_at":      expiredAt,
			"expired_at_unix": expiredAt.Unix(),
		}),
	}
}

func NewInfoSelfServiceVerificationSuccessful(channel string) *Message {
	return &Message{
		ID:   InfoSelfServiceVerificationSuccessful,
		Type: Success,
		Text: fmt.Sprintf("You successfully verified your %s.", channel),
		Context: context(map[string]any{
			"channel": channel,
		}),
	}
}

func NewErrorValidationVerificationTokenInvalidOrAlreadyUsed() *Message {
	return &Message{
		ID:   ErrorValidationVerificationTokenInvalidOrAlreadyUsed,
		Text: "The verification token is invalid or has already been used. Please retry the flow.",
		Type: Error,
	}
}

func NewErrorValidationVerificationRetrySuccess() *Message {
	return &Message{
		ID:   ErrorValidationVerificationRetrySuccess,
		Text: "The request was already completed successfully and can not be retried.",
		Type: Error,
	}
}

func NewErrorValidationVerificationStateFailure() *Message {
	return &Message{
		ID:   ErrorValidationVerificationStateFailure,
		Text: "The verification flow reached a failure state and must be retried.",
		Type: Error,
	}
}

func NewErrorValidationVerificationCodeInvalidOrAlreadyUsed() *Message {
	return &Message{
		ID:   ErrorValidationVerificationCodeInvalidOrAlreadyUsed,
		Text: "The verification code is invalid or has already been used. Please try again.",
		Type: Error,
	}
}

func NewVerificationCodeSent(channel, strategy string) *Message {
	return &Message{
		ID:   InfoSelfServiceVerificationCodeSent,
		Type: Info,
		Text: fmt.Sprintf("A verification %s has been sent to the %s you provided.", strategy, channel),
		Context: context(map[string]any{
			"strategy": strategy,
			"channel":  channel,
		}),
	}
}
