// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"net/http"
	"strings"
)

type (
	AuthConfig = struct {
		Type   string         `json:"type" koanf:"type"`
		Config map[string]any `json:"config" koanf:"config"`
	}
	ResponseConfig = struct {
		Parse  bool `json:"parse" koanf:"parse"`
		Ignore bool `json:"ignore" koanf:"ignore"`
	}
	Config struct {
		ID                 string            `json:"id" koanf:"id"`
		Method             string            `json:"method" koanf:"method"`
		URL                string            `json:"url" koanf:"url"`
		TemplateURI        string            `json:"body" koanf:"body"`
		Headers            map[string]string `json:"headers" koanf:"headers"`
		Auth               AuthConfig        `json:"auth" koanf:"auth"`
		EmitAnalyticsEvent *bool             `json:"emit_analytics_event" koanf:"emit_analytics_event"`
		CanInterrupt       bool              `json:"can_interrupt" koanf:"can_interrupt"`
		Response           ResponseConfig    `json:"response" koanf:"response"`

		auth   AuthStrategy
		header http.Header
	}
)

func (c *Config) UnmarshalJSON(raw []byte) error {
	type Alias Config
	var a Alias
	err := json.Unmarshal(raw, &a)
	if err != nil {
		return err
	}

	a.header = make(http.Header, len(a.Headers))

	_, ok := a.Headers["Content-Type"]
	if !ok {
		a.header.Set("Content-Type", ContentTypeJSON)
	}

	r := strings.NewReplacer("[[", "{{", "]]", "}}")
	for key, value := range a.Headers {
		if len(value) > 0 {
			v := value
			v = r.Replace(v)
			a.header.Set(key, v)
		} else {
			a.header.Set(key, value)
		}
	}

	*c = Config(a)

	return nil
}
