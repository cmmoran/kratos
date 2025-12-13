// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"fmt"

	"github.com/ory/x/stringsx"
)

func NewInfoNodeLabelVerifyOTP() *Message {
	return &Message{
		ID:   InfoNodeLabelVerifyOTP,
		Text: "Verify code",
		Type: Info,
	}
}

func NewInfoNodeLabelVerificationCode() *Message {
	return &Message{
		ID:   InfoNodeLabelVerificationCode,
		Text: "Verification code",
		Type: Info,
	}
}

func NewInfoNodeLabelRecoveryCode() *Message {
	return &Message{
		ID:   InfoNodeLabelRecoveryCode,
		Text: "Recovery code",
		Type: Info,
	}
}

func NewInfoNodeLabelRegistrationCode() *Message {
	return &Message{
		ID:   InfoNodeLabelRegistrationCode,
		Text: "Registration code",
		Type: Info,
	}
}

func NewInfoNodeLabelLoginCode() *Message {
	return &Message{
		ID:   InfoNodeLabelLoginCode,
		Text: "Login code",
		Type: Info,
	}
}

func NewInfoNodeInputPassword() *Message {
	return &Message{
		ID:   InfoNodeLabelInputPassword,
		Text: "Password",
		Type: Info,
	}
}

func NewInfoNodeLabelGenerated(title string, name string) *Message {
	return &Message{
		ID:   InfoNodeLabelGenerated,
		Text: title,
		Type: Info,
		Context: context(map[string]any{
			"title": title,
			"name":  name,
		}),
	}
}

func NewInfoNodeLabelSave() *Message {
	return &Message{
		ID:   InfoNodeLabelSave,
		Text: "Save",
		Type: Info,
	}
}

func NewInfoNodeLabelSubmit() *Message {
	return &Message{
		ID:   InfoNodeLabelSubmit,
		Text: "Submit",
		Type: Info,
	}
}

func NewInfoNodeLabelContinue() *Message {
	return &Message{
		ID:   InfoNodeLabelContinue,
		Text: "Continue",
		Type: Info,
	}
}

func NewInfoNodeLabelID() *Message {
	return &Message{
		ID:   InfoNodeLabelID,
		Text: "ID",
		Type: Info,
	}
}

func NewInfoNodeInputForChannel(channel string) *Message {
	return &Message{
		ID:   InfoNodeLabelChannel,
		Text: stringsx.ToUpperInitial(channel),
		Type: Info,
		Context: context(map[string]any{
			"channel": channel,
		}),
	}
}

func NewInfoNodeInputPhoneNumber() *Message {
	return &Message{
		ID:   InfoNodeLabelPhoneNumber,
		Text: "Phone number",
		Type: Info,
	}
}

func NewInfoNodeResendCodeVia(channel string) *Message {
	return &Message{
		ID:   InfoNodeLabelResendCode,
		Text: fmt.Sprintf("Resend code via %s", channel),
		Type: Info,
		Context: context(map[string]any{
			"channel": channel,
		}),
	}
}

func NewInfoNodeLoginAndLinkCredential() *Message {
	return &Message{
		ID:   InfoNodeLabelLoginAndLinkCredential,
		Text: "Login and link credential",
		Type: Info,
	}
}
