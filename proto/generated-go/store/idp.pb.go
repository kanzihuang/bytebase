// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: store/idp.proto

package store

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IdentityProviderType int32

const (
	IdentityProviderType_IDENTITY_PROVIDER_TYPE_UNSPECIFIED IdentityProviderType = 0
	IdentityProviderType_OAUTH2                             IdentityProviderType = 1
	IdentityProviderType_OIDC                               IdentityProviderType = 2
	IdentityProviderType_LDAP                               IdentityProviderType = 3
)

// Enum value maps for IdentityProviderType.
var (
	IdentityProviderType_name = map[int32]string{
		0: "IDENTITY_PROVIDER_TYPE_UNSPECIFIED",
		1: "OAUTH2",
		2: "OIDC",
		3: "LDAP",
	}
	IdentityProviderType_value = map[string]int32{
		"IDENTITY_PROVIDER_TYPE_UNSPECIFIED": 0,
		"OAUTH2":                             1,
		"OIDC":                               2,
		"LDAP":                               3,
	}
)

func (x IdentityProviderType) Enum() *IdentityProviderType {
	p := new(IdentityProviderType)
	*p = x
	return p
}

func (x IdentityProviderType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IdentityProviderType) Descriptor() protoreflect.EnumDescriptor {
	return file_store_idp_proto_enumTypes[0].Descriptor()
}

func (IdentityProviderType) Type() protoreflect.EnumType {
	return &file_store_idp_proto_enumTypes[0]
}

func (x IdentityProviderType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IdentityProviderType.Descriptor instead.
func (IdentityProviderType) EnumDescriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{0}
}

// SecurityProtocol represents the security protocol to be used when connecting
// to the LDAP server.
type SecurityProtocol int32

const (
	SecurityProtocol_Unspecified SecurityProtocol = 0
	// SecurityProtocolStartTLS represents the StartTLS security protocol.
	SecurityProtocol_StartTLS SecurityProtocol = 1
	// SecurityProtocolLDAPS represents the LDAPS security protocol.
	SecurityProtocol_LDAPS SecurityProtocol = 2
)

// Enum value maps for SecurityProtocol.
var (
	SecurityProtocol_name = map[int32]string{
		0: "Unspecified",
		1: "StartTLS",
		2: "LDAPS",
	}
	SecurityProtocol_value = map[string]int32{
		"Unspecified": 0,
		"StartTLS":    1,
		"LDAPS":       2,
	}
)

func (x SecurityProtocol) Enum() *SecurityProtocol {
	p := new(SecurityProtocol)
	*p = x
	return p
}

func (x SecurityProtocol) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SecurityProtocol) Descriptor() protoreflect.EnumDescriptor {
	return file_store_idp_proto_enumTypes[1].Descriptor()
}

func (SecurityProtocol) Type() protoreflect.EnumType {
	return &file_store_idp_proto_enumTypes[1]
}

func (x SecurityProtocol) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SecurityProtocol.Descriptor instead.
func (SecurityProtocol) EnumDescriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{1}
}

type IdentityProviderConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Config:
	//
	//	*IdentityProviderConfig_Oauth2Config
	//	*IdentityProviderConfig_OidcConfig
	//	*IdentityProviderConfig_LdapConfig
	Config isIdentityProviderConfig_Config `protobuf_oneof:"config"`
}

func (x *IdentityProviderConfig) Reset() {
	*x = IdentityProviderConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdentityProviderConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentityProviderConfig) ProtoMessage() {}

func (x *IdentityProviderConfig) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentityProviderConfig.ProtoReflect.Descriptor instead.
func (*IdentityProviderConfig) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{0}
}

func (m *IdentityProviderConfig) GetConfig() isIdentityProviderConfig_Config {
	if m != nil {
		return m.Config
	}
	return nil
}

func (x *IdentityProviderConfig) GetOauth2Config() *OAuth2IdentityProviderConfig {
	if x, ok := x.GetConfig().(*IdentityProviderConfig_Oauth2Config); ok {
		return x.Oauth2Config
	}
	return nil
}

func (x *IdentityProviderConfig) GetOidcConfig() *OIDCIdentityProviderConfig {
	if x, ok := x.GetConfig().(*IdentityProviderConfig_OidcConfig); ok {
		return x.OidcConfig
	}
	return nil
}

func (x *IdentityProviderConfig) GetLdapConfig() *LDAPIdentityProviderConfig {
	if x, ok := x.GetConfig().(*IdentityProviderConfig_LdapConfig); ok {
		return x.LdapConfig
	}
	return nil
}

type isIdentityProviderConfig_Config interface {
	isIdentityProviderConfig_Config()
}

type IdentityProviderConfig_Oauth2Config struct {
	Oauth2Config *OAuth2IdentityProviderConfig `protobuf:"bytes,1,opt,name=oauth2_config,json=oauth2Config,proto3,oneof"`
}

type IdentityProviderConfig_OidcConfig struct {
	OidcConfig *OIDCIdentityProviderConfig `protobuf:"bytes,2,opt,name=oidc_config,json=oidcConfig,proto3,oneof"`
}

type IdentityProviderConfig_LdapConfig struct {
	LdapConfig *LDAPIdentityProviderConfig `protobuf:"bytes,3,opt,name=ldap_config,json=ldapConfig,proto3,oneof"`
}

func (*IdentityProviderConfig_Oauth2Config) isIdentityProviderConfig_Config() {}

func (*IdentityProviderConfig_OidcConfig) isIdentityProviderConfig_Config() {}

func (*IdentityProviderConfig_LdapConfig) isIdentityProviderConfig_Config() {}

// OAuth2IdentityProviderConfig is the structure for OAuth2 identity provider config.
type OAuth2IdentityProviderConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthUrl       string        `protobuf:"bytes,1,opt,name=auth_url,json=authUrl,proto3" json:"auth_url,omitempty"`
	TokenUrl      string        `protobuf:"bytes,2,opt,name=token_url,json=tokenUrl,proto3" json:"token_url,omitempty"`
	UserInfoUrl   string        `protobuf:"bytes,3,opt,name=user_info_url,json=userInfoUrl,proto3" json:"user_info_url,omitempty"`
	ClientId      string        `protobuf:"bytes,4,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ClientSecret  string        `protobuf:"bytes,5,opt,name=client_secret,json=clientSecret,proto3" json:"client_secret,omitempty"`
	Scopes        []string      `protobuf:"bytes,6,rep,name=scopes,proto3" json:"scopes,omitempty"`
	FieldMapping  *FieldMapping `protobuf:"bytes,7,opt,name=field_mapping,json=fieldMapping,proto3" json:"field_mapping,omitempty"`
	SkipTlsVerify bool          `protobuf:"varint,8,opt,name=skip_tls_verify,json=skipTlsVerify,proto3" json:"skip_tls_verify,omitempty"`
}

func (x *OAuth2IdentityProviderConfig) Reset() {
	*x = OAuth2IdentityProviderConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OAuth2IdentityProviderConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OAuth2IdentityProviderConfig) ProtoMessage() {}

func (x *OAuth2IdentityProviderConfig) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OAuth2IdentityProviderConfig.ProtoReflect.Descriptor instead.
func (*OAuth2IdentityProviderConfig) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{1}
}

func (x *OAuth2IdentityProviderConfig) GetAuthUrl() string {
	if x != nil {
		return x.AuthUrl
	}
	return ""
}

func (x *OAuth2IdentityProviderConfig) GetTokenUrl() string {
	if x != nil {
		return x.TokenUrl
	}
	return ""
}

func (x *OAuth2IdentityProviderConfig) GetUserInfoUrl() string {
	if x != nil {
		return x.UserInfoUrl
	}
	return ""
}

func (x *OAuth2IdentityProviderConfig) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *OAuth2IdentityProviderConfig) GetClientSecret() string {
	if x != nil {
		return x.ClientSecret
	}
	return ""
}

func (x *OAuth2IdentityProviderConfig) GetScopes() []string {
	if x != nil {
		return x.Scopes
	}
	return nil
}

func (x *OAuth2IdentityProviderConfig) GetFieldMapping() *FieldMapping {
	if x != nil {
		return x.FieldMapping
	}
	return nil
}

func (x *OAuth2IdentityProviderConfig) GetSkipTlsVerify() bool {
	if x != nil {
		return x.SkipTlsVerify
	}
	return false
}

// OIDCIdentityProviderConfig is the structure for OIDC identity provider config.
type OIDCIdentityProviderConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Issuer        string        `protobuf:"bytes,1,opt,name=issuer,proto3" json:"issuer,omitempty"`
	ClientId      string        `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ClientSecret  string        `protobuf:"bytes,3,opt,name=client_secret,json=clientSecret,proto3" json:"client_secret,omitempty"`
	FieldMapping  *FieldMapping `protobuf:"bytes,4,opt,name=field_mapping,json=fieldMapping,proto3" json:"field_mapping,omitempty"`
	SkipTlsVerify bool          `protobuf:"varint,5,opt,name=skip_tls_verify,json=skipTlsVerify,proto3" json:"skip_tls_verify,omitempty"`
}

func (x *OIDCIdentityProviderConfig) Reset() {
	*x = OIDCIdentityProviderConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OIDCIdentityProviderConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OIDCIdentityProviderConfig) ProtoMessage() {}

func (x *OIDCIdentityProviderConfig) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OIDCIdentityProviderConfig.ProtoReflect.Descriptor instead.
func (*OIDCIdentityProviderConfig) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{2}
}

func (x *OIDCIdentityProviderConfig) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}

func (x *OIDCIdentityProviderConfig) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *OIDCIdentityProviderConfig) GetClientSecret() string {
	if x != nil {
		return x.ClientSecret
	}
	return ""
}

func (x *OIDCIdentityProviderConfig) GetFieldMapping() *FieldMapping {
	if x != nil {
		return x.FieldMapping
	}
	return nil
}

func (x *OIDCIdentityProviderConfig) GetSkipTlsVerify() bool {
	if x != nil {
		return x.SkipTlsVerify
	}
	return false
}

// LDAPIdentityProviderConfig is the structure for LDAP identity provider config.
type LDAPIdentityProviderConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host             string           `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Port             int64            `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	BindDn           string           `protobuf:"bytes,3,opt,name=bind_dn,json=bindDn,proto3" json:"bind_dn,omitempty"`
	BindPassword     string           `protobuf:"bytes,4,opt,name=bind_password,json=bindPassword,proto3" json:"bind_password,omitempty"`
	BaseDn           string           `protobuf:"bytes,5,opt,name=base_dn,json=baseDn,proto3" json:"base_dn,omitempty"`
	UserFilter       string           `protobuf:"bytes,6,opt,name=user_filter,json=userFilter,proto3" json:"user_filter,omitempty"`
	SecurityProtocol SecurityProtocol `protobuf:"varint,7,opt,name=security_protocol,json=securityProtocol,proto3,enum=bytebase.store.SecurityProtocol" json:"security_protocol,omitempty"`
	FieldMapping     *FieldMapping    `protobuf:"bytes,8,opt,name=field_mapping,json=fieldMapping,proto3" json:"field_mapping,omitempty"`
	SkipTlsVerify    bool             `protobuf:"varint,9,opt,name=skip_tls_verify,json=skipTlsVerify,proto3" json:"skip_tls_verify,omitempty"`
}

func (x *LDAPIdentityProviderConfig) Reset() {
	*x = LDAPIdentityProviderConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LDAPIdentityProviderConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LDAPIdentityProviderConfig) ProtoMessage() {}

func (x *LDAPIdentityProviderConfig) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LDAPIdentityProviderConfig.ProtoReflect.Descriptor instead.
func (*LDAPIdentityProviderConfig) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{3}
}

func (x *LDAPIdentityProviderConfig) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *LDAPIdentityProviderConfig) GetPort() int64 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *LDAPIdentityProviderConfig) GetBindDn() string {
	if x != nil {
		return x.BindDn
	}
	return ""
}

func (x *LDAPIdentityProviderConfig) GetBindPassword() string {
	if x != nil {
		return x.BindPassword
	}
	return ""
}

func (x *LDAPIdentityProviderConfig) GetBaseDn() string {
	if x != nil {
		return x.BaseDn
	}
	return ""
}

func (x *LDAPIdentityProviderConfig) GetUserFilter() string {
	if x != nil {
		return x.UserFilter
	}
	return ""
}

func (x *LDAPIdentityProviderConfig) GetSecurityProtocol() SecurityProtocol {
	if x != nil {
		return x.SecurityProtocol
	}
	return SecurityProtocol_Unspecified
}

func (x *LDAPIdentityProviderConfig) GetFieldMapping() *FieldMapping {
	if x != nil {
		return x.FieldMapping
	}
	return nil
}

func (x *LDAPIdentityProviderConfig) GetSkipTlsVerify() bool {
	if x != nil {
		return x.SkipTlsVerify
	}
	return false
}

// FieldMapping saves the field names from user info API of identity provider.
// As we save all raw json string of user info response data into `principal.idp_user_info`,
// we can extract the relevant data based with `FieldMapping`.
//
// e.g. For GitHub authenticated user API, it will return `login`, `name` and `email` in response.
// Then the identifier of FieldMapping will be `login`, display_name will be `name`,
// and email will be `email`.
// reference: https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
type FieldMapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Identifier is the field name of the unique identifier in 3rd-party idp user info. Required.
	Identifier string `protobuf:"bytes,1,opt,name=identifier,proto3" json:"identifier,omitempty"`
	// DisplayName is the field name of display name in 3rd-party idp user info. Required.
	DisplayName string `protobuf:"bytes,2,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Email is the field name of primary email in 3rd-party idp user info. Required.
	Email string `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
}

func (x *FieldMapping) Reset() {
	*x = FieldMapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FieldMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FieldMapping) ProtoMessage() {}

func (x *FieldMapping) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FieldMapping.ProtoReflect.Descriptor instead.
func (*FieldMapping) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{4}
}

func (x *FieldMapping) GetIdentifier() string {
	if x != nil {
		return x.Identifier
	}
	return ""
}

func (x *FieldMapping) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *FieldMapping) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

type IdentityProviderUserInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Identifier is the value of the unique identifier in 3rd-party idp user info.
	Identifier string `protobuf:"bytes,1,opt,name=identifier,proto3" json:"identifier,omitempty"`
	// DisplayName is the value of display name in 3rd-party idp user info.
	DisplayName string `protobuf:"bytes,2,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Email is the value of primary email in 3rd-party idp user info.
	Email string `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
}

func (x *IdentityProviderUserInfo) Reset() {
	*x = IdentityProviderUserInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_idp_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdentityProviderUserInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentityProviderUserInfo) ProtoMessage() {}

func (x *IdentityProviderUserInfo) ProtoReflect() protoreflect.Message {
	mi := &file_store_idp_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentityProviderUserInfo.ProtoReflect.Descriptor instead.
func (*IdentityProviderUserInfo) Descriptor() ([]byte, []int) {
	return file_store_idp_proto_rawDescGZIP(), []int{5}
}

func (x *IdentityProviderUserInfo) GetIdentifier() string {
	if x != nil {
		return x.Identifier
	}
	return ""
}

func (x *IdentityProviderUserInfo) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *IdentityProviderUserInfo) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

var File_store_idp_proto protoreflect.FileDescriptor

var file_store_idp_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x69, 0x64, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x0e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x22, 0x95, 0x02, 0x0a, 0x16, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x50, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x53, 0x0a, 0x0d,
	0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x2e, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x48, 0x00, 0x52, 0x0c, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x12, 0x4d, 0x0a, 0x0b, 0x6f, 0x69, 0x64, 0x63, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61, 0x73,
	0x65, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x4f, 0x49, 0x44, 0x43, 0x49, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x48, 0x00, 0x52, 0x0a, 0x6f, 0x69, 0x64, 0x63, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x4d, 0x0a, 0x0b, 0x6c, 0x64, 0x61, 0x70, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61, 0x73, 0x65,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x4c, 0x44, 0x41, 0x50, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x48, 0x00, 0x52, 0x0a, 0x6c, 0x64, 0x61, 0x70, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42,
	0x08, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0xbf, 0x02, 0x0a, 0x1c, 0x4f, 0x41,
	0x75, 0x74, 0x68, 0x32, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x75,
	0x74, 0x68, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x75,
	0x74, 0x68, 0x55, 0x72, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x75,
	0x72, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x55,
	0x72, 0x6c, 0x12, 0x22, 0x0a, 0x0d, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f,
	0x75, 0x72, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x75, 0x73, 0x65, 0x72, 0x49,
	0x6e, 0x66, 0x6f, 0x55, 0x72, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x49, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73,
	0x12, 0x41, 0x0a, 0x0d, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61,
	0x73, 0x65, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x0c, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x12, 0x26, 0x0a, 0x0f, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x74, 0x6c, 0x73, 0x5f,
	0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x73, 0x6b,
	0x69, 0x70, 0x54, 0x6c, 0x73, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x22, 0xe1, 0x01, 0x0a, 0x1a,
	0x4f, 0x49, 0x44, 0x43, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x73,
	0x73, 0x75, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x73, 0x73, 0x75,
	0x65, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12,
	0x23, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x12, 0x41, 0x0a, 0x0d, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x62, 0x79,
	0x74, 0x65, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x46, 0x69, 0x65,
	0x6c, 0x64, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x0c, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x26, 0x0a, 0x0f, 0x73, 0x6b, 0x69, 0x70, 0x5f,
	0x74, 0x6c, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0d, 0x73, 0x6b, 0x69, 0x70, 0x54, 0x6c, 0x73, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x22,
	0xf6, 0x02, 0x0a, 0x1a, 0x4c, 0x44, 0x41, 0x50, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x62, 0x69, 0x6e, 0x64, 0x5f, 0x64,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x62, 0x69, 0x6e, 0x64, 0x44, 0x6e, 0x12,
	0x23, 0x0a, 0x0d, 0x62, 0x69, 0x6e, 0x64, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x62, 0x69, 0x6e, 0x64, 0x50, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x64, 0x6e, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x62, 0x61, 0x73, 0x65, 0x44, 0x6e, 0x12, 0x1f, 0x0a,
	0x0b, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x75, 0x73, 0x65, 0x72, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x4d,
	0x0a, 0x11, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x62, 0x79, 0x74, 0x65,
	0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x53, 0x65, 0x63, 0x75, 0x72,
	0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x52, 0x10, 0x73, 0x65, 0x63,
	0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x41, 0x0a,
	0x0d, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x62, 0x79, 0x74, 0x65, 0x62, 0x61, 0x73, 0x65, 0x2e,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x70, 0x70, 0x69,
	0x6e, 0x67, 0x52, 0x0c, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x12, 0x26, 0x0a, 0x0f, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x74, 0x6c, 0x73, 0x5f, 0x76, 0x65, 0x72,
	0x69, 0x66, 0x79, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x73, 0x6b, 0x69, 0x70, 0x54,
	0x6c, 0x73, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x22, 0x67, 0x0a, 0x0c, 0x46, 0x69, 0x65, 0x6c,
	0x64, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x1e, 0x0a, 0x0a, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70,
	0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65,
	0x6d, 0x61, 0x69, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x22, 0x73, 0x0a, 0x18, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x55, 0x73, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1e, 0x0a,
	0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x12, 0x21, 0x0a,
	0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2a, 0x5e, 0x0a, 0x14, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x12, 0x26,
	0x0a, 0x22, 0x49, 0x44, 0x45, 0x4e, 0x54, 0x49, 0x54, 0x59, 0x5f, 0x50, 0x52, 0x4f, 0x56, 0x49,
	0x44, 0x45, 0x52, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49,
	0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x4f, 0x41, 0x55, 0x54, 0x48, 0x32,
	0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x4f, 0x49, 0x44, 0x43, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04,
	0x4c, 0x44, 0x41, 0x50, 0x10, 0x03, 0x2a, 0x3c, 0x0a, 0x10, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69,
	0x74, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x6e,
	0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x53,
	0x74, 0x61, 0x72, 0x74, 0x54, 0x4c, 0x53, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x4c, 0x44, 0x41,
	0x50, 0x53, 0x10, 0x02, 0x42, 0x14, 0x5a, 0x12, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65,
	0x64, 0x2d, 0x67, 0x6f, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_store_idp_proto_rawDescOnce sync.Once
	file_store_idp_proto_rawDescData = file_store_idp_proto_rawDesc
)

func file_store_idp_proto_rawDescGZIP() []byte {
	file_store_idp_proto_rawDescOnce.Do(func() {
		file_store_idp_proto_rawDescData = protoimpl.X.CompressGZIP(file_store_idp_proto_rawDescData)
	})
	return file_store_idp_proto_rawDescData
}

var file_store_idp_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_store_idp_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_store_idp_proto_goTypes = []interface{}{
	(IdentityProviderType)(0),            // 0: bytebase.store.IdentityProviderType
	(SecurityProtocol)(0),                // 1: bytebase.store.SecurityProtocol
	(*IdentityProviderConfig)(nil),       // 2: bytebase.store.IdentityProviderConfig
	(*OAuth2IdentityProviderConfig)(nil), // 3: bytebase.store.OAuth2IdentityProviderConfig
	(*OIDCIdentityProviderConfig)(nil),   // 4: bytebase.store.OIDCIdentityProviderConfig
	(*LDAPIdentityProviderConfig)(nil),   // 5: bytebase.store.LDAPIdentityProviderConfig
	(*FieldMapping)(nil),                 // 6: bytebase.store.FieldMapping
	(*IdentityProviderUserInfo)(nil),     // 7: bytebase.store.IdentityProviderUserInfo
}
var file_store_idp_proto_depIdxs = []int32{
	3, // 0: bytebase.store.IdentityProviderConfig.oauth2_config:type_name -> bytebase.store.OAuth2IdentityProviderConfig
	4, // 1: bytebase.store.IdentityProviderConfig.oidc_config:type_name -> bytebase.store.OIDCIdentityProviderConfig
	5, // 2: bytebase.store.IdentityProviderConfig.ldap_config:type_name -> bytebase.store.LDAPIdentityProviderConfig
	6, // 3: bytebase.store.OAuth2IdentityProviderConfig.field_mapping:type_name -> bytebase.store.FieldMapping
	6, // 4: bytebase.store.OIDCIdentityProviderConfig.field_mapping:type_name -> bytebase.store.FieldMapping
	1, // 5: bytebase.store.LDAPIdentityProviderConfig.security_protocol:type_name -> bytebase.store.SecurityProtocol
	6, // 6: bytebase.store.LDAPIdentityProviderConfig.field_mapping:type_name -> bytebase.store.FieldMapping
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_store_idp_proto_init() }
func file_store_idp_proto_init() {
	if File_store_idp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_store_idp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdentityProviderConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_store_idp_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OAuth2IdentityProviderConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_store_idp_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OIDCIdentityProviderConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_store_idp_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LDAPIdentityProviderConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_store_idp_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FieldMapping); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_store_idp_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdentityProviderUserInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_store_idp_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*IdentityProviderConfig_Oauth2Config)(nil),
		(*IdentityProviderConfig_OidcConfig)(nil),
		(*IdentityProviderConfig_LdapConfig)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_store_idp_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_store_idp_proto_goTypes,
		DependencyIndexes: file_store_idp_proto_depIdxs,
		EnumInfos:         file_store_idp_proto_enumTypes,
		MessageInfos:      file_store_idp_proto_msgTypes,
	}.Build()
	File_store_idp_proto = out.File
	file_store_idp_proto_rawDesc = nil
	file_store_idp_proto_goTypes = nil
	file_store_idp_proto_depIdxs = nil
}
