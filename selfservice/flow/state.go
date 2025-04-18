// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"

	"github.com/pkg/errors"
)

// State
//
// The state represents the state of the verification flow.
//
// - choose_method: ask the user to choose a method (e.g. recover account via email)
// - sent_email: the email has been sent to the user
// - passed_challenge: the request was successful and the recovery challenge was passed.
// - show_form: a form is shown to the user to perform the flow
// - success: the flow has been completed successfully
//
// swagger:enum selfServiceFlowState
type State string

// #nosec G101 -- only a key constant
const (
	StateChooseMethod    State = "choose_method"
	StateEmailSent       State = "sent_email"
	StateSmsSent         State = "sent_sms"
	StatePassedChallenge State = "passed_challenge"
	StateShowForm        State = "show_form"
	StateSuccess         State = "success"
)

type StateKey string

func keyFor(current State, via ...string) StateKey {
	if len(via) == 0 {
		return StateKey(current.String())
	}
	return StateKey(current.String() + "_" + via[0])
}

var states = map[StateKey]State{
	keyFor(StateChooseMethod):          StateEmailSent,
	keyFor(StateChooseMethod, "email"): StateEmailSent,
	keyFor(StateChooseMethod, "sms"):   StateSmsSent,
	keyFor(StateEmailSent):             StatePassedChallenge,
	keyFor(StateSmsSent):               StatePassedChallenge,
	keyFor(StatePassedChallenge):       StatePassedChallenge,
}

var statesOrder = []State{
	StateChooseMethod,
	StateEmailSent,
	StateSmsSent,
	StatePassedChallenge,
}

func indexOf(current State) int {
	for k, s := range statesOrder {
		if s == current {
			return k
		}
	}
	return 0
}

func HasReachedState(expected, actual State) bool {
	if expected == StateSmsSent {
		expected = StateEmailSent
	}
	if actual == StateSmsSent {
		actual = StateEmailSent
	}
	return indexOf(actual) >= indexOf(expected)
}

func NextState(current State, via ...string) State {
	if state, ok := states[keyFor(current, via...)]; ok {
		return state
	}

	return StateChooseMethod
}

// For some reason using sqlxx.NullString as the State type does not work here.
// Reimplementing the Scanner interface on type State does work and allows
// the state to be NULL in the database.

// MarshalJSON returns m as the JSON encoding of m.
func (ns State) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(ns))
}

// UnmarshalJSON sets *m to a copy of data.
func (ns *State) UnmarshalJSON(data []byte) error {
	if ns == nil {
		return errors.New("json.RawMessage: UnmarshalJSON on nil pointer")
	}
	if len(data) == 0 {
		return nil
	}
	return errors.WithStack(json.Unmarshal(data, (*string)(ns)))
}

// Scan implements the Scanner interface.
func (ns *State) Scan(value interface{}) error {
	var v sql.NullString
	if err := (&v).Scan(value); err != nil {
		return err
	}
	*ns = State(v.String)
	return nil
}

// Value implements the driver Valuer interface.
func (ns State) Value() (driver.Value, error) {
	if len(ns) == 0 {
		return sql.NullString{}.Value()
	}
	return sql.NullString{Valid: true, String: string(ns)}.Value()
}

// String implements the Stringer interface.
func (ns State) String() string {
	return string(ns)
}
