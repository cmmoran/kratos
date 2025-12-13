// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/herodot"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlxx"
)

// Update Settings Flow with Lookup Method
//
// swagger:model updateSettingsFlowWithCodeMethod
type updateSettingsFlowWithCodeMethod struct {
	// CodeEnable if set to true will enable the code credential method
	CodeEnable bool `json:"code_enable"`

	// CodeEnable if set to true will disable the code credential method
	CodeDisable bool `json:"code_disable"`

	// DeviceUntrust if set, will untrust this device id for this aal2 method for this account
	DeviceUntrust string `json:"code_device_untrust"`

	// CSRFToken is the anti-CSRF token
	CSRFToken string `json:"csrf_token"`

	// Method
	//
	// Should be set to "code" when trying to enable or disable the credential method.
	//
	// required: true
	Method string `json:"method"`

	// Flow is flow ID.
	//
	// swagger:ignore
	Flow string `json:"flow"`

	// Transient data to pass along to any webhooks
	//
	// required: false
	TransientPayload json.RawMessage `json:"transient_payload,omitempty" form:"transient_payload"`
}

func (p *updateSettingsFlowWithCodeMethod) GetFlowID() uuid.UUID {
	return x.ParseUUID(p.Flow)
}

func (p *updateSettingsFlowWithCodeMethod) SetFlowID(rid uuid.UUID) {
	p.Flow = rid.String()
}

func (s *Strategy) SettingsStrategyID() string {
	return identity.CredentialsTypeCodeAuth.String()

}

func (s *Strategy) RegisterSettingsRoutes(_ *x.RouterPublic) {
}

func (s *Strategy) PopulateSettingsMethod(ctx context.Context, r *http.Request, i *identity.Identity, f *settings.Flow) (err error) {
	_, span := s.deps.Tracer(ctx).Tracer().Start(ctx, "selfservice.strategy.password.Strategy.PopulateSettingsMethod")
	defer otelx.End(span, &err)

	f.UI.SetCSRF(s.deps.GenerateCSRFToken(r))
	hasCode, err := s.identityHasCode(ctx, i)
	if err != nil {
		return err
	}
	if hasCode {
		s.deps.Audit().WithRequest(r).WithField("has_code", hasCode).Info("code credentials enabled for account")
		var devices []session.Device
		devices, err = s.deps.SessionPersister().ListTrustedDevicesByIdentityWithExpiration(ctx, i.ID, s.deps.Config().SecurityTrustDeviceDuration(ctx))
		if err != nil {
			return err
		}
		deviceNode := NewTrustedDevicesCodeNode(devices)
		f.UI.Nodes.Append(node.NewInputField(node.CodeDisable, "true", node.CodeGroup, node.InputAttributeTypeSubmit, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoSelfServiceSettingsDisableLookup()))
		if deviceNode != nil {
			f.UI.Nodes.Upsert(deviceNode)
		}
	} else {
		s.deps.Audit().WithRequest(r).WithField("has_code", hasCode).Info("code credentials missing")
		f.UI.Nodes.Append(node.NewInputField(node.CodeEnable, "true", node.CodeGroup, node.InputAttributeTypeSubmit, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoSelfServiceSettingsEnableMethod()))
	}

	return nil
}

func (s *Strategy) Settings(ctx context.Context, w http.ResponseWriter, r *http.Request, f *settings.Flow, sess *session.Session) (_ *settings.UpdateContext, err error) {
	ctx, span := s.deps.Tracer(ctx).Tracer().Start(ctx, "selfservice.strategy.code.Strategy.Settings")
	defer otelx.End(span, &err)

	var p updateSettingsFlowWithCodeMethod
	ctxUpdate, err := settings.PrepareUpdate(s.deps, w, r, f, sess, settings.ContinuityKey(s.SettingsStrategyID()), &p)
	if errors.Is(err, settings.ErrContinuePreviousAction) {
		return ctxUpdate, s.continueSettingsFlow(ctx, r, ctxUpdate, p)
	} else if err != nil {
		return ctxUpdate, s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if err = s.decodeSettingsFlow(r, &p); err != nil {
		return ctxUpdate, s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if p.CodeEnable || p.CodeDisable || len(p.DeviceUntrust) > 0 {
		p.Method = s.SettingsStrategyID()
		if err := flow.MethodEnabledAndAllowed(ctx, f.GetFlowName(), s.SettingsStrategyID(), p.Method, s.deps); err != nil {
			return nil, s.handleSettingsError(w, r, ctxUpdate, p, err)
		}
	} else {
		span.SetAttributes(attribute.String("not_responsible_reason", "neither code enable nor code disable was set"))
		return nil, errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	// This does not come from the payload!
	p.Flow = ctxUpdate.Flow.ID.String()
	if err = s.continueSettingsFlow(ctx, r, ctxUpdate, p); err != nil {
		return ctxUpdate, s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	return ctxUpdate, nil

}

func (s *Strategy) continueSettingsFlow(ctx context.Context, r *http.Request, ctxUpdate *settings.UpdateContext, p updateSettingsFlowWithCodeMethod) error {
	if p.CodeEnable || p.CodeDisable || len(p.DeviceUntrust) > 0 {
		if err := flow.MethodEnabledAndAllowed(ctx, flow.SettingsFlow, s.SettingsStrategyID(), s.SettingsStrategyID(), s.deps); err != nil {
			return err
		}

		if err := flow.EnsureCSRF(s.deps, r, ctxUpdate.Flow.Type, s.deps.Config().DisableAPIFlowEnforcement(ctx), s.deps.GenerateCSRFToken, p.CSRFToken); err != nil {
			return err
		}

		if ctxUpdate.Session.AuthenticatedAt.Add(s.deps.Config().SelfServiceFlowSettingsPrivilegedSessionMaxAge(ctx)).Before(time.Now()) {
			return errors.WithStack(settings.NewFlowNeedsReAuth())
		}
	} else {
		return errors.New("ended up in unexpected state")
	}

	var (
		i   *identity.Identity
		err error
	)
	if len(p.DeviceUntrust) > 0 {
		i, err = s.continueSettingsFlowDeviceUntrust(ctx, ctxUpdate, p)
		s.deps.Audit().WithField("code_device_untrust", p.DeviceUntrust).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("untrusting device code code mfa")
	} else if p.CodeEnable {
		i, err = s.continueSettingsFlowEnable(ctx, ctxUpdate, p)
		s.deps.Audit().WithField("code_enable", p.CodeEnable).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("code credentials should be enabled")
	} else if p.CodeDisable {
		i, err = s.continueSettingsFlowDisable(ctx, ctxUpdate, p)
		s.deps.Audit().WithField("code_disable", p.CodeDisable).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("code credentials should be disabled")
	}

	ctxUpdate.UpdateIdentity(i)

	return err
}

func (s *Strategy) continueSettingsFlowDeviceUntrust(ctx context.Context, ctxUpdate *settings.UpdateContext, p updateSettingsFlowWithCodeMethod) (*identity.Identity, error) {
	s.deps.Audit().WithField("code_device_untrust", p.DeviceUntrust).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("untrusting code mfa device for account")

	i, err := s.deps.PrivilegedIdentityPool().GetIdentityConfidential(ctx, ctxUpdate.Session.Identity.ID)
	if err != nil {
		return nil, err
	}
	devId := uuid.FromStringOrNil(p.DeviceUntrust)
	if devId == uuid.Nil {
		return nil, errors.WithStack(errors.New("invalid device id"))
	}

	var devices []session.Device
	devices, err = s.deps.SessionPersister().ListTrustedDevicesByIdentity(ctx, i.ID)
	if err != nil {
		return nil, err
	}
	for idx, d := range devices {
		if d.ID == devId {
			devices[idx].Trusted = false
			if err = s.deps.SessionPersister().UpsertDevice(ctx, &(devices[idx])); err != nil {
				return nil, err
			}
		}
	}
	deviceNode := NewTrustedDevicesCodeNode(devices)
	ctxUpdate.Flow.UI.Nodes.Upsert(node.NewInputField(node.CodeDisable, "true", node.CodeGroup, node.InputAttributeTypeSubmit, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoSelfServiceSettingsDisableLookup()))
	if deviceNode != nil {
		ctxUpdate.Flow.UI.Nodes.Upsert(deviceNode)
	}

	ctxUpdate.UpdateIdentity(i)

	if err = s.deps.SettingsFlowPersister().UpdateSettingsFlow(ctx, ctxUpdate.Flow); err != nil {
		return nil, err
	}

	s.deps.Audit().Info("finished continueSettingsFlowCodeUntrustDevice")

	return i, nil
}

func (s *Strategy) continueSettingsFlowEnable(ctx context.Context, ctxUpdate *settings.UpdateContext, p updateSettingsFlowWithCodeMethod) (*identity.Identity, error) {
	s.deps.Audit().WithField("code_enable", p.CodeEnable).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("enabling code credentials for identity")
	ctxUpdate.Flow.UI.Nodes.Upsert(node.NewInputField(node.CodeDisable, "true", node.CodeGroup, node.InputAttributeTypeSubmit, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoSelfServiceSettingsEnableMethod()))

	i, err := s.deps.PrivilegedIdentityPool().GetIdentityConfidential(ctx, ctxUpdate.Session.Identity.ID)
	if err != nil {
		return nil, err
	}

	creds := i.GetCredentialsOr(identity.CredentialsTypeCodeAuth, &identity.Credentials{
		Type:        identity.CredentialsTypeCodeAuth,
		Identifiers: []string{},
		Config:      sqlxx.JSONRawMessage(`{"disabled": false}`),
		Version:     1,
	})
	// Check if the credentials config is valid JSON
	if !gjson.Valid(string(creds.Config)) {
		return i, nil
	}

	var conf identity.CredentialsCode
	if err = json.Unmarshal(creds.Config, &conf); err != nil {
		return i, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to unmarshal credentials config: %s", err))
	}

	conf.Disabled = false
	if creds.Config, err = json.Marshal(conf); err != nil {
		return i, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to marshal credentials config: %s", err))
	}
	i.SetCredentials(identity.CredentialsTypeCodeAuth, *creds)
	// Since we added the method, it also means that we have authenticated it
	if err = s.deps.SessionManager().SessionAddAuthenticationMethods(ctx, ctxUpdate.Session.ID, session.AuthenticationMethod{
		Method: s.ID(),
		AAL:    identity.AuthenticatorAssuranceLevel2,
	}); err != nil {
		return nil, err
	}

	ctxUpdate.UpdateIdentity(i)

	if err = s.deps.SettingsFlowPersister().UpdateSettingsFlow(ctx, ctxUpdate.Flow); err != nil {
		return nil, err
	}

	s.deps.Audit().Info("finished continueSettingsFlowEnable")

	return i, nil
}

func (s *Strategy) continueSettingsFlowDisable(ctx context.Context, ctxUpdate *settings.UpdateContext, p updateSettingsFlowWithCodeMethod) (*identity.Identity, error) {
	s.deps.Audit().WithField("code_disable", p.CodeDisable).WithField("identity", ctxUpdate.Session.Identity.ID.String()).Info("disabling code credentials for identity")
	ctxUpdate.Flow.UI.Nodes.Upsert(node.NewInputField(node.CodeEnable, "true", node.CodeGroup, node.InputAttributeTypeSubmit, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoSelfServiceSettingsEnableMethod()))

	i, err := s.deps.PrivilegedIdentityPool().GetIdentityConfidential(ctx, ctxUpdate.Session.Identity.ID)
	if err != nil {
		return nil, err
	}

	if creds, ok := i.GetCredentials(identity.CredentialsTypeCodeAuth); ok {
		// Check if the credentials config is valid JSON
		if !gjson.Valid(string(creds.Config)) {
			return i, nil
		}

		var conf identity.CredentialsCode
		if err = json.Unmarshal(creds.Config, &conf); err != nil {
			return i, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to unmarshal credentials config: %s", err))
		}

		conf.Disabled = true
		if creds.Config, err = json.Marshal(conf); err != nil {
			return i, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to marshal credentials config: %s", err))
		}
		i.SetCredentials(identity.CredentialsTypeCodeAuth, *creds)

		if devices, derr := s.deps.SessionPersister().ListTrustedDevicesByIdentity(ctx, ctxUpdate.Session.Identity.ID); derr == nil {
			for idx, d := range devices {
				if d.Trusted && d.DeviceTrustedFor(s.ID()) {
					devices[idx].Trusted = false
					if err = s.deps.SessionPersister().UpsertDevice(ctx, &(devices[idx])); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	ctxUpdate.UpdateIdentity(i)

	if err = s.deps.SettingsFlowPersister().UpdateSettingsFlow(ctx, ctxUpdate.Flow); err != nil {
		return nil, err
	}

	s.deps.Audit().Info("finished continueSettingsFlowDisable")

	return i, nil
}

func (s *Strategy) decodeSettingsFlow(r *http.Request, dest interface{}) error {
	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(settingsSchema)
	if err != nil {
		return errors.WithStack(err)
	}

	return decoderx.NewHTTP().Decode(r, dest, compiler,
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderAllowedMethods("POST", "GET"),
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.HTTPDecoderJSONFollowsFormFormat(),
	)
}

func (s *Strategy) identityHasCode(ctx context.Context, id *identity.Identity) (bool, error) {
	if len(id.Credentials) == 0 {
		if err := s.deps.PrivilegedIdentityPool().HydrateIdentityAssociations(ctx, id, identity.ExpandCredentials); err != nil {
			return false, err
		}
	}

	count, err := s.CountActiveMultiFactorCredentials(ctx, id.Credentials)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (s *Strategy) handleSettingsError(w http.ResponseWriter, r *http.Request, ctxUpdate *settings.UpdateContext, p updateSettingsFlowWithCodeMethod, err error) error {
	// Do not pause flow if the flow type is an API flow as we can't save cookies in those flows.
	if e := new(settings.FlowNeedsReAuth); errors.As(err, &e) && ctxUpdate.Flow != nil && ctxUpdate.Flow.Type == flow.TypeBrowser {
		if err := s.deps.ContinuityManager().Pause(r.Context(), w, r, settings.ContinuityKey(s.SettingsStrategyID()), settings.ContinuityOptions(p, ctxUpdate.GetSessionIdentity())...); err != nil {
			return err
		}
	}

	if ctxUpdate.Flow != nil {
		ctxUpdate.Flow.UI.ResetMessages()
		ctxUpdate.Flow.UI.SetCSRF(s.deps.GenerateCSRFToken(r))
	}

	return err
}
