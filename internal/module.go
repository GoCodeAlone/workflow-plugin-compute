package internal

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type providerConfig struct {
	ServerURL       string `json:"server_url"`
	AuthTokenRef    string `json:"auth_token_ref"`
	RequestTimeout  string `json:"request_timeout,omitempty"`
	DefaultOrgID    string `json:"default_org_id,omitempty"`
	DefaultPoolID   string `json:"default_pool_id,omitempty"`
	DefaultPolicyID string `json:"default_policy_id,omitempty"`
}

type providerModule struct {
	name   string
	config providerConfig
}

func newProviderModule(name string, raw map[string]any) (*providerModule, error) {
	var cfg providerConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("compute.provider %q: %w", name, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("compute.provider %q: %w", name, err)
	}
	return &providerModule{name: name, config: cfg}, nil
}

func (c providerConfig) validate() error {
	var errs []error
	if c.ServerURL == "" {
		errs = append(errs, errors.New("server_url is required"))
	} else if u, err := url.ParseRequestURI(c.ServerURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		errs = append(errs, fmt.Errorf("server_url must be absolute http(s) URL"))
	}
	if c.AuthTokenRef == "" {
		errs = append(errs, errors.New("auth_token_ref is required"))
	} else if !isRef(c.AuthTokenRef) {
		errs = append(errs, errors.New("auth_token_ref must be a secret: or config: ref"))
	}
	if c.RequestTimeout != "" {
		if _, err := time.ParseDuration(c.RequestTimeout); err != nil {
			errs = append(errs, fmt.Errorf("request_timeout must be duration: %w", err))
		}
	}
	return errors.Join(errs...)
}

func isRef(value string) bool {
	return strings.HasPrefix(value, "secret:") || strings.HasPrefix(value, "config:")
}

func (m *providerModule) Init() error {
	return nil
}

func (m *providerModule) Start(context.Context) error {
	return nil
}

func (m *providerModule) Stop(context.Context) error {
	return nil
}

type poolConfig struct {
	ProviderRef string            `json:"provider_ref"`
	OrgID       string            `json:"org_id"`
	PoolID      string            `json:"pool_id"`
	PolicyID    string            `json:"policy_id"`
	Mode        string            `json:"mode"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type poolModule struct {
	name   string
	config poolConfig
}

func newPoolModule(name string, raw map[string]any) (*poolModule, error) {
	var cfg poolConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("compute.pool %q: %w", name, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("compute.pool %q: %w", name, err)
	}
	return &poolModule{name: name, config: cfg}, nil
}

func (c poolConfig) validate() error {
	var errs []error
	if c.ProviderRef == "" {
		errs = append(errs, errors.New("provider_ref is required"))
	}
	if c.OrgID == "" {
		errs = append(errs, errors.New("org_id is required"))
	}
	if c.PoolID == "" {
		errs = append(errs, errors.New("pool_id is required"))
	}
	if c.PolicyID == "" {
		errs = append(errs, errors.New("policy_id is required"))
	}
	switch c.Mode {
	case "private", "priority", "public":
	case "":
		errs = append(errs, errors.New("mode is required"))
	default:
		errs = append(errs, fmt.Errorf("mode must be private, priority, or public"))
	}
	return errors.Join(errs...)
}

func (m *poolModule) Init() error {
	return nil
}

func (m *poolModule) Start(context.Context) error {
	return nil
}

func (m *poolModule) Stop(context.Context) error {
	return nil
}

func providerModuleSchema() sdk.ModuleSchemaData {
	return sdk.ModuleSchemaData{
		Type:        "compute.provider",
		Label:       "Compute Provider",
		Category:    "Compute",
		Description: "Connection settings for a workflow-compute control plane.",
		ConfigFields: []sdk.ConfigField{
			{Name: "server_url", Type: "string", Description: "Base URL for the compute control plane.", Required: true},
			{Name: "auth_token_ref", Type: "string", Description: "Workflow secret/config ref for the API bearer token.", Required: true},
			{Name: "request_timeout", Type: "string", Description: "Optional request timeout duration."},
			{Name: "default_org_id", Type: "string", Description: "Optional default organization id."},
			{Name: "default_pool_id", Type: "string", Description: "Optional default pool id."},
			{Name: "default_policy_id", Type: "string", Description: "Optional default policy id."},
		},
	}
}

func poolModuleSchema() sdk.ModuleSchemaData {
	return sdk.ModuleSchemaData{
		Type:        "compute.pool",
		Label:       "Compute Pool",
		Category:    "Compute",
		Description: "Default org, pool, and policy routing for compute tasks.",
		ConfigFields: []sdk.ConfigField{
			{Name: "provider_ref", Type: "string", Description: "Name of the compute.provider module.", Required: true},
			{Name: "org_id", Type: "string", Description: "Organization id for submitted work.", Required: true},
			{Name: "pool_id", Type: "string", Description: "Pool id for submitted work.", Required: true},
			{Name: "policy_id", Type: "string", Description: "Policy id for submitted work.", Required: true},
			{Name: "mode", Type: "string", Description: "Pool mode.", Required: true, Options: []string{"private", "priority", "public"}},
		},
	}
}
