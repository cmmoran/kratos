// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
)

type (
	Auth struct {
		Type   string
		Config json.RawMessage
	}

	Config struct {
		Method      string          `json:"method"`
		URL         string          `json:"url"`
		TemplateURI string          `json:"body"`
		Header      http.Header     `json:"-"`
		RawHeader   json.RawMessage `json:"headers"`
		Auth        Auth            `json:"auth"`
	}
)

func (c *Config) UnmarshalJSON(raw []byte) error {
	type Alias Config
	var a Alias
	err := json.Unmarshal(raw, &a)
	if err != nil {
		return err
	}

	rawHeader := gjson.ParseBytes(a.RawHeader).Map()
	a.Header = make(http.Header, len(rawHeader))

	_, ok := rawHeader["Content-Type"]
	if !ok {
		a.Header.Set("Content-Type", ContentTypeJSON)
	}

	r := strings.NewReplacer("[[", "{{", "]]", "}}")
	for key, value := range rawHeader {
		if len(value.String()) > 0 {
			v := value.String()
			v = r.Replace(v)
			a.Header.Set(key, v)
		} else {
			a.Header.Set(key, value.String())
		}
	}

	*c = Config(a)

	return nil
}
