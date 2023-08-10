// Package ldap is the plugin for LDAP Identity Provider.
package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"

	storepb "github.com/bytebase/bytebase/proto/generated-go/store"
)

// IdentityProvider represents an LDAP Identity Provider.
type IdentityProvider struct {
	config *storepb.LDAPIdentityProviderConfig
}

// SecurityProtocol represents the security protocol to be used when connecting
// to the LDAP server.
type SecurityProtocol string

const (
	// SecurityProtocolStartTLS represents the StartTLS security protocol.
	SecurityProtocolStartTLS SecurityProtocol = "starttls"
	// SecurityProtocolLDAPS represents the LDAPS security protocol.
	SecurityProtocolLDAPS SecurityProtocol = "ldaps"
)

// NewIdentityProvider initializes a new LDAP Identity Provider with the given
// configuration.
func NewIdentityProvider(config *storepb.LDAPIdentityProviderConfig) (*IdentityProvider, error) {
	if config.SecurityProtocol != storepb.SecurityProtocol_Unspecified && config.SecurityProtocol != storepb.SecurityProtocol_StartTLS && config.SecurityProtocol != storepb.SecurityProtocol_LDAPS {
		return nil, errors.Errorf("the field %q must be either %q or %q", "securityProtocol", SecurityProtocolStartTLS, SecurityProtocolLDAPS)
	}
	for v, field := range map[string]string{
		config.Host:                    "host",
		config.BindDn:                  "bindDn",
		config.BindPassword:            "bindPassword",
		config.BaseDn:                  "baseDn",
		config.UserFilter:              "userFilter",
		config.FieldMapping.Identifier: "fieldMapping.identifier",
	} {
		if v == "" {
			return nil, errors.Errorf("the field %q is empty but required", field)
		}
	}

	if config.Port <= 0 {
		if config.SecurityProtocol == storepb.SecurityProtocol_LDAPS {
			config.Port = 636
		} else {
			config.Port = 389
		}
	}

	return &IdentityProvider{
		config: config,
	}, nil
}

func (p *IdentityProvider) dial() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)
	tlsConfig := &tls.Config{
		ServerName:         p.config.Host,
		InsecureSkipVerify: p.config.SkipTlsVerify,
	}
	if p.config.SecurityProtocol == storepb.SecurityProtocol_LDAPS {
		conn, err := ldap.DialTLS("tcp", addr, tlsConfig)
		if err != nil {
			return nil, errors.Errorf("dial TLS: %v", err)
		}
		return conn, nil
	}

	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		return nil, errors.Errorf("dial: %v", err)
	}
	if p.config.SecurityProtocol == storepb.SecurityProtocol_StartTLS {
		if err = conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, errors.Errorf("start TLS: %v", err)
		}
	}
	return conn, nil
}

// Authenticate authenticates the user with the given username and password.
func (p *IdentityProvider) Authenticate(username, password string) (*storepb.IdentityProviderUserInfo, error) {
	conn, err := p.dial()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Bind with a system account
	err = conn.Bind(p.config.BindDn, p.config.BindPassword)
	if err != nil {
		return nil, errors.Errorf("bind: %v", err)
	}

	sr, err := conn.Search(
		ldap.NewSearchRequest(
			p.config.BaseDn,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			strings.ReplaceAll(p.config.UserFilter, "%s", username),
			[]string{"dn", p.config.FieldMapping.Identifier, p.config.FieldMapping.DisplayName, p.config.FieldMapping.Email},
			nil,
		),
	)
	if err != nil {
		return nil, errors.Errorf("search user DN: %v", err)
	} else if len(sr.Entries) != 1 {
		return nil, errors.Errorf("expect 1 user DN but got %d", len(sr.Entries))
	}
	entry := sr.Entries[0]

	// Bind as the user to verify their password
	err = conn.Bind(entry.DN, password)
	if err != nil {
		return nil, errors.Errorf("bind user %s: %v", entry.DN, err)
	}

	identifier := entry.GetAttributeValue(p.config.FieldMapping.Identifier)
	if identifier == "" {
		return nil, errors.Errorf("the attribute %q is not found or has empty value", p.config.FieldMapping.Identifier)
	}
	return &storepb.IdentityProviderUserInfo{
		Identifier:  identifier,
		DisplayName: entry.GetAttributeValue(p.config.FieldMapping.DisplayName),
		Email:       entry.GetAttributeValue(p.config.FieldMapping.Email),
	}, nil
}
