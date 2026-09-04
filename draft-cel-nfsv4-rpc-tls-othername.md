---
title: "Remote Procedure Call Identity Squashing via x.509 Certificate Fields"
abbrev: "SunRPC x.509 Identity Squashing"
category: std

docname: draft-cel-nfsv4-rpc-tls-othername-latest
pi: [toc, sortrefs, symrefs, docmapping]
stand_alone: yes
v: 3

ipr: trust200902
area: "Web and Internet Transport"
workgroup: "Network File System Version 4"
obsoletes:
keyword:
 - x.509
 - SubjectAltName
 - otherName
 - NFS
 - SunRPC

author:
 -
    fullname: Rick Macklem
    organization: FreeBSD Project
    abbrev: FreeBSD
    country: Canada
    email: rmacklem@uoguelph.ca
 -
    fullname: Chuck Lever
    role: editor
    country: United States of America
    email: cel-ietf@chucklever.net

venue:
  group: nfsv4
  type: Working Group
  mail: nfsv4@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/nfsv4/
  repo: https://github.com/chucklever/i-d-rpc-tls-othername
  latest: https://chucklever.github.io/i-d-rpc-tls-othername/#go.draft-cel-nfsv4-rpc-tls-othername.html

--- abstract

This document extends RPC-with-TLS so that a client's x.509
certificate may carry instructions to the RPC server to execute all
RPC transactions from that client as a single user identity.

--- middle

# Introduction

## Background

The Remote Procedure Call version 2 protocol (RPC, for short) has been
a Proposed Standard for three decades (see {{!RFC5531}} and its
antecedents).
Upper layer protocols such as the Network File System family
({{!RFC8881}}) are based on RPC.

In 2022, the IETF published {{!RFC9289}}, which specifies a mechanism
by which RPC transactions can be cryptographically protected during
transit. RFC 9289 provides confidentiality and integrity of RPC
traffic and authenticates the communicating peers.

## Problem Statement

{{Section 4.2 of RFC9289}} states that:

> RPC user authentication is not affected by
> the use of transport layer security.  When a client presents a TLS
> peer identity to an RPC server, the protocol extension described in
> the current document provides no way for the server to know whether
> that identity represents one RPC user on that client or is shared
> amongst many RPC users.  Therefore, a server implementation cannot
> utilize the remote TLS peer identity to authenticate RPC users.

Mobile devices such as laptops are typically used by a single user and
do not have a fixed, well-known IP address or fully qualified DNS name.
Without either, the server has fewer verification checks available on
the client's X.509 certificate.  This extension allows a server to
restrict access from such a client to a single user identity, limiting
exposure if that certificate is compromised.

When a service runs in a dedicated VM or container, it often runs as
a single assigned user identity. Kerberos is poorly suited here:
TGTs expire in hours, yet the service may run for much longer. This
extension lets the client convey that identity in the certificate,
which does not expire on the same short cycle as a TGT.

This document calls the replacement of incoming RPC user identities
with a single user identity "identity squashing".

## Summary of Proposed Solution

To enable interoperable implementations of RPC identity squashing,
this document specifies the use of the x.509 SubjectAltName otherName
field to carry an RPC user identity.  The document defines an object
identifier for the otherName "type-id" field, the corresponding
"value" field format, and normative guidance on how RPC servers
interpret that value.

# Requirements Language

{::boilerplate bcp14-tagged}

# x.509 Certificate SubjectAltName Field

As specified in {{Section 4.2.1.6 of !RFC5280}}:

> The subjectAltName MAY carry additional name types through the use of
> the otherName field.  The format and semantics of the name are
> indicated through the OBJECT IDENTIFIER in the type-id field.  The
> name itself is conveyed as value field in otherName.

A SubjectAltName extension MAY contain multiple entries of different types
(e.g., dNSName, iPAddress, otherName). When processing a certificate for
identity squashing purposes, the server examines only the otherName entries
with type-id values defined in this document. Other SubjectAltName entries
are used for their normal purposes (such as hostname verification for TLS).

This document specifies new uses of the otherName field to name an
RPC user identity. The RPC server derives an RPC user from that
identity when the TLS session is established. For
each RPC request within the TLS session that carries an AUTH_NONE or
AUTH_SYS credential, the server executes the request under the
derived RPC user in place of the one the credential asserts.

The derivation depends on the identity form. An RPCAuthSys value
carries a numeric UID and GIDs, and the server uses them directly.
A GSSExportedName value names a GSS-API principal, and the server
derives the RPC user from it as it does from the principal of an
RPCSEC_GSS security context. An NFSv4Principal value carries a
user@domain string, and the server resolves it through the mapping
it applies to the NFSv4 owner attribute. A server that cannot
derive an RPC user from the identity the certificate names is
unable to apply the identity, and {{sec-server-processing}}
specifies what it does then.

Identity squashing does not apply to a request that carries an
RPCSEC_GSS credential {{!RFC2203}}. Such a request is processed under
the identity established by its GSS security context, which
{{Section 4.2.1 of RFC9289}} leaves unchanged by the use of TLS. An
RPCSEC_GSS credential carries a context handle rather than a user
identity, and the peer that established that context has already
proven its identity to the server. Replacing it would also discard
the machine credential over which SP4_MACH_CRED state protection
({{Section 18.35 of RFC8881}}) is defined.

## Server Processing of otherName Fields {#sec-server-processing}

When an RPC server receives a client certificate containing a
SubjectAltName extension, it MUST process the otherName fields as
follows:

1. The server MUST examine all otherName entries in the SubjectAltName
extension.

1. If the server finds an otherName with a type-id that matches one of
the identity squashing OIDs defined in this document (id-on-rpcAuthSys,
id-on-gssExportedName, or id-on-nfsv4Principal), it MUST extract
and validate the identity information from that otherName and derive
an RPC user from it.

1. If multiple identity squashing otherName fields are present in the
same SubjectAltName extension, the server MUST reject the certificate
to avoid ambiguity. See {{sec-security-considerations}} for details.

1. If the server encounters otherName entries with type-id values it does
not recognize, it MUST ignore those entries and continue processing.

1. Other types of SubjectAltName entries (dNSName, iPAddress, etc.) are
processed independently and do not affect identity squashing behavior.

The server performs identity squashing only if it successfully validates
an identity squashing otherName field and authorizes its use for the
authenticated TLS peer.

If the server recognizes an identity squashing type-id but cannot
validate the identity that otherName carries, cannot derive an RPC
user from it, or does not authorize its use for the authenticated
TLS peer, the server MUST reject every non-NULL procedure on that TLS
session that carries an AUTH_NONE or AUTH_SYS credential with a
reply_stat of MSG_DENIED, a reject_stat of AUTH_ERROR, and an
auth_stat of AUTH_TOOWEAK, as defined in {{Section 9 of !RFC5531}}.
The server MUST
NOT fall back to the credential carried in the RPC header. Such a
fallback would grant the client the access its header credential
asserts, which is the access the certificate was meant to withhold.

## Server Policy {#sec-server-policy}

A server that implements this specification either enforces identity
squashing or has it disabled. The scope at which a server sets that
policy, whether for the whole server, per export, or per some other
unit, is a local matter.

A server on which identity squashing is disabled MUST ignore the
identity squashing otherName entries in a client certificate and
process RPC requests as a server that does not implement this
specification does ({{sec-interop}}). A client cannot distinguish the
two.

A server that enforces identity squashing applies
{{sec-server-processing}} to every client certificate it receives.
On a connection for which no certificate identity has been applied,
the server MUST reject every non-NULL procedure that carries an
AUTH_NONE or AUTH_SYS credential with a reply_stat of MSG_DENIED, a
reject_stat of AUTH_ERROR, and an auth_stat of AUTH_TOOWEAK. That
covers a connection with no TLS session, a TLS session on which the
client presented no certificate, and a TLS session whose certificate
carries no identity squashing otherName, in addition to the case
{{sec-server-processing}} specifies. An enforcing server never
executes such a request under the credential carried in the RPC
header. A request that carries an RPCSEC_GSS credential is processed
under its GSS security context under either policy.

## Server Processing

This section provides a non-normative example of how an RPC server
implementation might process identity squashing otherName fields.
Implementers are free to use alternative approaches.

A typical server processing flow might include these steps:

1. During TLS session establishment, extract and validate the client's
X.509 certificate according to {{RFC5280}} and {{RFC9289}}.

1. If the certificate contains a SubjectAltName extension, examine each
otherName entry to determine if any contain identity squashing type-id
values (id-on-rpcAuthSys, id-on-gssExportedName, or id-on-nfsv4Principal).

1. If exactly one identity squashing otherName is found, extract and parse
the identity information according to the ASN.1 definition for that type-id.
If parsing fails, reject the certificate.

1. Derive an RPC user from the identity. For RPCAuthSys, take the UID and
GIDs as given. For GSSExportedName, map the principal as the server maps
the principal of an RPCSEC_GSS context. For NFSv4Principal, resolve the
user@domain string through the server's NFSv4 owner mapping. If the
derivation fails, treat the identity as one the server cannot apply.

1. Perform authorization checks to determine whether the authenticated TLS
peer is permitted to use the specified identity. This might involve:
   - Consulting an access control list mapping certificate subjects to
     allowed user identities
   - Verifying that the requested UID/GID values are within acceptable ranges
   - Validating that the user@domain string matches expected domain patterns
   - Checking that the GSS-API mechanism is trusted and the principal is
     authorized

1. If authorization succeeds, associate the derived RPC user with the TLS
session state.

1. For each incoming RPC request on this TLS session that carries an
AUTH_NONE or AUTH_SYS credential, execute the request under the RPC user
derived from the certificate, for all authorization and access control
decisions. The credential information in the RPC header is ignored. A
request that carries an RPCSEC_GSS credential is processed under its GSS
security context, as it would be on any other TLS session.

Parsing and validating the certificate once at TLS session establishment
and caching the result avoids per-request overhead.

## Interoperability with Non-Supporting Servers {#sec-interop}

RPC servers that do not implement this specification do not recognize
the otherName OIDs defined in this document. {{Section 4.2 of RFC5280}}
requires a certificate-using system to reject a certificate that carries
an unrecognized critical extension, and permits it to ignore an
unrecognized non-critical one. Neither rule reaches an unrecognized
type-id within a subjectAltName extension, which {{Section 4.2 of
RFC5280}} lists among the extensions that a conforming application
recognizes.

This document cannot impose a requirement on servers that do not
implement it. Such servers are expected to ignore otherName entries
whose type-id they do not recognize, and to process RPC requests using
the credential information contained in the RPC header, subject to
their normal authentication and authorization policies. That
expectation is convention rather than a requirement inherited from
{{RFC5280}}.

Issuing a certificate that carries one of the otherName fields defined
in this document does not by itself restrict the access available to
the certificate holder. The restriction takes effect only on servers
that implement this specification and enforce identity squashing
({{sec-server-policy}}). {{sec-security-considerations}}
recommends that servers maintain trust anchors for identity squashing
certificates separate from those used solely for TLS peer
authentication.

## Certificate Profile

A certificate carrying one of the otherName fields defined in this
document MUST contain a non-empty subject distinguished name, and its
subjectAltName extension MUST NOT be marked critical.

{{Section 4.2.1.6 of RFC5280}} requires a critical subjectAltName
extension when the subject field contains an empty sequence. A server
that does not implement this specification and encounters a critical
subjectAltName carrying only an unrecognized type-id may reject the
certificate, because {{Section 4.2 of RFC5280}} directs a
certificate-using system to reject a critical extension that contains
information it cannot process. {{RFC5280}} does not settle whether an
unrecognized type-id within a recognized extension is such
information. A non-empty subject distinguished name keeps the
subjectAltName extension non-critical, which removes the rejection
outcome and leaves the fall-through described in {{sec-interop}}.

## Client Requirements

A client that presents a certificate carrying one of the otherName
fields defined in this document MUST use a security policy that
requires a TLS session on every connection to the RPC server, as
described in {{Section 6.1.1 of RFC9289}}. If the AUTH_TLS probe does
not elicit a "STARTTLS" token, or if the subsequent TLS handshake
fails, the client MUST NOT continue RPC operation on that connection.

The AUTH_TLS probe occurs in cleartext. Without such a policy, an
on-path attacker can alter the probe to make it appear that the server
does not support TLS. RPC operation then continues with no certificate
presented, and the server applies its normal policy to the credential
carried in each RPC header. For AUTH_SYS that credential is asserted
by the client and is not verified, so the attacker replaces the
identity named in the certificate with whatever identity the client
sends.

A client MUST NOT present a certificate carrying one of the otherName
fields defined in this document on a TLS session over which it
transmits RPC requests for more than one RPC user. A client that
multiplexes RPC users onto one session can still use this mechanism by
opening a separate TLS session, authenticated with such a certificate,
for the user that certificate names.

{{Section 6.2 of RFC9289}} observes that a client's TLS credentials
are potentially visible to every RPC user that shares a TLS session.
Under {{RFC9289}} alone, a local user who reaches the shared
credential still faces the server's per-user authorization. A server
that applies identity squashing discards the credential carried in the
RPC header. Reaching the session is then the whole of the
authorization, and every request on it is attributed to the identity
named in the certificate.

## AUTH_SYS Identities

### otherName OID for AUTH_SYS

The otherName OID for AUTH_SYS identities is id-on-rpcAuthSys,
defined in {{sec-asn1}}.

### Format of the otherName Value

The otherName value for AUTH_SYS identities contains an RPCAuthSys
structure as defined in {{sec-asn1}}. This structure consists
of a 32-bit unsigned integer specifying a numeric UID, and a sequence
of 32-bit unsigned integers specifying numeric GIDs. The integers
have the meaning that the AUTH_SYS authentication flavor gives them
in Appendix A of {{!RFC5531}}.

RPCAuthSys names an identity in the terms AUTH_SYS uses. It is not an
AUTH_SYS credential, and a server does not build an authsys_parms
structure from it. The per-call stamp and the machinename fields of
authsys_parms are therefore absent, since a stamp has no meaning in a
certificate and TLS has already authenticated the client host.

The first element of gids is the effective GID. Any further elements
are supplementary GIDs. When gids is empty, the server supplies the
effective GID and the supplementary GIDs from its own user database
entry for the UID.

The 16-element bound that {{RFC5531}} places on the gids array of
authsys_parms does not apply, because the server derives a local
identity rather than a wire credential. A server whose local
representation cannot hold every GID in the sequence MUST treat the
identity as one it cannot apply rather than silently truncate the
list.

## GSS-API Principals

### otherName OID for GSS-API Principals

The otherName OID for GSS-API exported names is id-on-gssExportedName,
defined in {{sec-asn1}}.

### Format of the otherName Value

The otherName value contains a GSSExportedName structure as defined in
{{sec-asn1}}, consisting of a GSS-API mechanism OID and a
mechanism-specific exported name value as described in {{Section 3.2 of !RFC2743}}.

## NFSv4 User @ Domain String Identities

### otherName OID for String Identities

The otherName OID for NFSv4 user@domain principals is id-on-nfsv4Principal,
defined in {{sec-asn1}}.

### Format of the otherName Value

The otherName value contains an NFSv4Principal structure as defined in
{{sec-asn1}}, consisting of a UTF-8 encoded user name, the
literal "@" character, and a UTF-8 encoded domain name. This is the
form that {{Section 5.9 of ?RFC8881}} uses for the owner attribute.
The string MUST contain the "@" character. {{RFC8881}} gives a
string without "@" a meaning of its own, that no translation was
available at the sender, which does not apply to a certificate.

The server derives the RPC user by resolving the string through the
same mapping it applies to the owner attribute. {{RFC8881}} leaves
that mapping to the implementation, and this document does not
specify it further. A server whose mapping does not handle the
domain part of the string can resolve only strings whose domain
matches its own.

This form carries an identity that belongs to an upper-layer
protocol rather than to RPC. The RPCAuthSys and GSSExportedName forms
name identities in terms the RPC layer already uses for its AUTH_SYS
and RPCSEC_GSS flavors. The user@domain string is the representation
that NFSv4 defines for its owner and owner_group attributes, and
resolving it requires the owner mapping of an NFSv4 server. An RPC
server for another program has no such mapping and cannot apply this
form. The form is therefore suited to NFSv4 servers, and a deployment
that spans other RPC services chooses one of the other two.

# Extending This Mechanism

RPC servers might in future implement other forms of RPC user
identity, such as Windows Security Identifiers. Standards Action can
extend the mechanism specified in this document to a new form. A
document that defines a new identity type:

- MUST define an ASN.1 module.
- MUST request an IANA OID allocation.
- SHOULD provide security considerations specific to that identity type.
- SHOULD provide examples and test vectors.

# Client Certificate Generation

This section provides non-normative guidance for Certificate Authorities
and administrators who generate client certificates containing identity
squashing otherName fields.

## Choosing an Identity Format

The choice of which identity format to use depends on the deployment
environment:

RPCAuthSys
: Appropriate for environments where numeric UIDs and GIDs are the primary
  form of user identity, such as traditional UNIX/Linux systems. This format
  is compact but requires that UID/GID mappings be consistent between the
  certificate and the server's user database.

GSSExportedName
: Suitable for servers that key user identities by GSS-API principal
  name, such as servers already deployed with Kerberos. Identity
  squashing applies only to AUTH_NONE and AUTH_SYS requests, so this
  format names the principal those requests execute under and leaves
  RPCSEC_GSS requests, which prove a principal of their own, untouched.
  One use is a host with no keytab whose users hold Kerberos principals:
  the certificate names a service principal the server already knows, so
  the host's non-GSS traffic executes as that principal while its users'
  RPCSEC_GSS traffic keeps their own identities. Servers must support
  the mechanism indicated by the nameType OID.

NFSv4Principal
: Suited to NFSv4 servers, which already resolve user@domain strings
  through their owner mapping, and to deployments where human-readable
  identities are preferred. The format is familiar to administrators
  and supports internationalization, but it names an NFSv4 identity
  rather than an RPC one, so RPC servers for other programs cannot
  apply it.

## Populating Identity Fields

When generating certificates, consider these guidelines:

UID/GID values
: Ensure that the numeric values in RPCAuthSys correspond to valid entries
  in the server's user database. List the effective GID first, followed
  by any supplementary GIDs, or leave gids empty to have the server
  supply the groups from its own user database. Avoid privileged UIDs
  (such as 0 for root) unless there is a specific operational
  requirement and strong authorization controls are in place.

GSS-API exported names
: The nameValue field should contain a properly formatted exported name
  token as defined by the specific GSS-API mechanism. For Kerberos, this
  follows the format specified in {{?RFC4121}}. Consult the mechanism
  specification for proper encoding.

User@domain strings
: Both the user and domain components should be UTF-8 encoded. Domain names
  should typically match the DNS domain under which the server operates.
  International domain names should be encoded in UTF-8, not in Punycode
  (ACE) form.

## Certificate Validity Period

Certificates containing identity squashing otherName fields grant access
to server resources under a specific user identity. Administrators should
choose validity periods to suit their security requirements. Shorter
validity periods reduce the window of exposure if a certificate is
compromised, but increase the operational overhead of renewal.

Administrators should also factor in how quickly certificate revocation
(CRL or OCSP) propagates in their environment, since that affects how
long a compromised certificate remains usable after revocation.

# Implementation Status

{:aside}
> RFC Editor: This section is to be removed before publishing this document as an RFC.

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of this
Internet-Draft, and is based on a proposal described in
{{?RFC7942}}. The description of implementations in this section is
intended to assist the IETF in its decision processes in progressing
drafts to RFCs.

Please note that the listing of any individual implementation here
does not imply endorsement by the IETF. Furthermore, no effort has
been spent to verify the information presented here that was supplied
by IETF contributors. This is not intended as, and must not be
construed to be, a catalog of available implementations or their
features. Readers are advised to note that other implementations may
exist.

## FreeBSD NFS Server and Client

Organization:
: FreeBSD

URL:
: <https://www.freebsd.org>

Maturity:
: Complete.

Coverage:
: The mechanism to represent user@domain strings has been implemented
  using an OID from the FreeBSD arc.

Licensing:
: BSD 3-clause

Implementation experience:
: None to report

# Security Considerations {#sec-security-considerations}

## General Security Considerations

The security considerations in {{Section 8 of RFC9289}} apply to this
specification, including the discussion of certificate validation, trust
anchors, and TLS session establishment.

## Identity Squashing and Authorization

This specification enables a client to request that all RPC operations within a
TLS session be executed under a single user identity specified in the client's
X.509 certificate. This "identity squashing" mechanism has several security
implications:

### Trust in the Certificate Authority

Servers MUST limit which Certificate Authorities (CAs) they trust to
issue certificates carrying the otherName extensions defined in this
document.  A compromised or malicious CA could issue certificates that
grant access to server resources under arbitrary user identities.

Servers SHOULD maintain separate trust anchors for identity squashing
certificates and certificates used solely for TLS peer authentication,
giving administrators direct control over which CAs may assert user
identities.

### Authorization Decisions

The presence of an otherName field specifying a user identity does not by itself
grant any authorization. Servers MUST perform their normal authorization checks
to determine whether the requested identity is permitted for the authenticated
TLS peer.

For example, a server might maintain an access control list mapping certificate
subjects or distinguished names to the set of user identities they are permitted
to assume. Only if such authorization succeeds should the server execute RPC
operations under the specified identity.

### Absence of Enforcement

An RPC server that does not implement this specification, or that
implements it with identity squashing disabled ({{sec-server-policy}}),
processes RPC requests using the credential carried in each RPC
header. For AUTH_SYS that credential is asserted by the client and is
not verified.

Identity squashing therefore fails toward greater privilege. An
administrator who issues these certificates expecting access to be
confined to one identity gets no such confinement from a server that
does not enforce it, and the client cannot tell whether the server
applied the certificate identity. Other identity policies that an RPC
server applies without announcing them, such as mapping UID 0 to an
unprivileged identity or deriving the group list from the server's own
user database, fail toward lesser privilege instead.

A client can confirm that a server enforces identity squashing by
presenting a certificate that carries no identity squashing otherName
and observing AUTH_TOOWEAK. A server that ignores the otherName gives
the client no signal, so a client cannot distinguish a server with
identity squashing disabled from one that does not implement this
specification.

A deployment cannot rely on the presence of these otherName fields as
an access restriction. The restriction exists only where the server
enforces it.

### Name Resolution

#### NFSv4 Principals

When processing NFSv4Principal otherName values, servers MUST resolve
the string through the same mapping they apply to the NFSv4 owner
attribute, and MUST treat a string that mapping cannot resolve as an
identity the server cannot apply. {{RFC8881}} does not specify that
mapping, so how the domain is validated, how an internationalized
domain name is normalized, and whether names are case-sensitive are
properties of the server's mapping. Applying one mapping to both the
certificate and the owner attribute keeps a given string resolving to
one local identity on a given server.

#### GSS-API Exported Names

When processing GSSExportedName otherName values, servers MUST verify that:

- The mechanism OID in the nameType field corresponds to a GSS-API mechanism
  the server supports and trusts
- The nameValue field conforms to the exported name format defined by that
  specific GSS-API mechanism
- The mechanism-specific name validation and canonicalization procedures are
  followed

Servers MUST derive the RPC user from the exported name as they derive
it from the principal of an RPCSEC_GSS security context established
under the same mechanism, and MUST treat a name that derivation cannot
map as an identity the server cannot apply.

Servers SHOULD NOT accept exported names from GSS-API mechanisms they do not
fully support, as improper name handling could lead to authorization bypass
vulnerabilities.

#### AUTH_SYS Identities

When processing RPCAuthSys otherName values, servers MUST:

- Validate that the UID and GIDs fall within acceptable ranges for the local
  system's user database
- Verify that the UID corresponds to a valid user account
- Confirm that the GIDs represent valid groups and that the user is authorized
  to be a member of those groups

Servers SHOULD reject certificates containing UID 0 (root) or other privileged
UIDs unless there is an explicit and well-justified operational requirement,
and additional strong authorization controls are in place.

## Session Binding

All RPC requests within a TLS session containing an identity squashing
otherName that carry an AUTH_NONE or AUTH_SYS credential execute under the
same user identity. Requests that carry an RPCSEC_GSS credential execute
under the identity of their GSS security context, and the certificate
identity is not bound to them. Servers MUST ensure that session state
cannot be hijacked or transferred between different TLS sessions, as this could
allow an attacker to gain the privileges associated with the squashed identity.

## Revocation

Servers SHOULD support certificate revocation checking (via CRL, OCSP, or similar
mechanisms) for certificates containing identity squashing otherName fields.
Since these certificates grant user-level access to server resources, timely
revocation is critical when a certificate is compromised or a user's access
should be terminated.

## Privacy Considerations

The otherName fields defined in this specification reveal user identity
information in the client's X.509 certificate, which is transmitted
during the TLS handshake. {{Section 5 of RFC9289}} forbids negotiating
TLS versions prior to 1.3, and TLS 1.3 encrypts the client certificate,
so a network observer does not see the identity in transit.

## Multiple Identity Formats

Implementations MUST NOT allow multiple identity squashing otherName fields to be
present simultaneously in the same SubjectAltName extension. If multiple such
fields are present (e.g., both RPCAuthSys and NFSv4Principal), the server MUST
reject the certificate to avoid ambiguity about which identity should be used.

# IANA Considerations {#sec-iana-considerations}

## SMI Security for PKIX Module Identifier

IANA is requested to assign an object identifier for the ASN.1 module
specified in this document in the "SMI Security for PKIX Module Identifier"
registry (1.3.6.1.5.5.7.0):

| Decimal | Description                       | References  |
|:--------|:----------------------------------|:------------|
| TBD1    | id-mod-rpc-tls-identity-squashing | RFC-TBD     |

## SMI Security for PKIX Other Name Forms

IANA is requested to assign three object identifiers for the otherName
types specified in this document in the "SMI Security for PKIX Other
Name Forms" registry (1.3.6.1.5.5.7.8):

| Decimal | Description                       | References  |
|:--------|:----------------------------------|:------------|
| TBD2    | id-on-rpcAuthSys                  | RFC-TBD     |
| TBD3    | id-on-gssExportedName             | RFC-TBD     |
| TBD4    | id-on-nfsv4Principal              | RFC-TBD     |

These otherName identifiers are used in the SubjectAltName extension
of X.509 certificates to carry RPC user identity information for the
purpose of identity squashing as described in this document.

"RFC-TBD" is to be replaced with the actual RFC number when this
document is published.

--- back

# ASN.1 Module {#sec-asn1}

The following ASN.1 module normatively specifies the structure of
the new otherName values described in this document.
This specification uses the ASN.1 definitions from
{{?RFC5912}} with the 2002 ASN.1 notation used in that document.
{{?RFC5912}} updates normative documents using older ASN.1 notation.

## RPC TLS Identity Squashing Module

~~~ asn.1
RPCTLSIdentitySquashing
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-rpc-tls-identity-squashing(TBD) }

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

IMPORTS
    OTHER-NAME
    FROM PKIX1Implicit-2009
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-mod(0)
          id-mod-pkix1-implicit-02(59) } ;

-- Object Identifier Arc
id-pkix OBJECT IDENTIFIER ::=
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) }

id-on OBJECT IDENTIFIER ::= { id-pkix 8 }  -- other names

-- ===================================================================
-- RPC AUTH_SYS Identity Squashing
-- ===================================================================

-- OID for RPC AUTH_SYS credentials in otherName
id-on-rpcAuthSys OBJECT IDENTIFIER ::= { id-on TBD }

-- RPC AUTH_SYS Identity Structure
-- UID and GID list in the terms of the RPC AUTH_SYS authentication
-- flavor, RFC 5531 Appendix A.  Not an AUTH_SYS credential: the
-- stamp and machinename fields are absent and gids is unbounded.
RPCAuthSys ::= SEQUENCE {
    uid        INTEGER (0..4294967295),  -- 32-bit UID
    gids       SEQUENCE OF INTEGER (0..4294967295)
               -- Effective GID first, then supplementary GIDs
}

-- For use in SubjectAltName otherName
rpcAuthSys OTHER-NAME ::= {
    RPCAuthSys IDENTIFIED BY id-on-rpcAuthSys
}

-- ===================================================================
-- GSS-API Exported Name Identity Squashing
-- ===================================================================

-- OID for GSS-API Exported Name in otherName
id-on-gssExportedName OBJECT IDENTIFIER ::= { id-on TBD }

-- GSS-API Exported Name Structure
-- As defined in RFC 2743 Section 3.2
GSSExportedName ::= SEQUENCE {
    nameType   OBJECT IDENTIFIER,  -- GSS-API mechanism OID
    nameValue  OCTET STRING        -- Mechanism-specific exported name
}

-- For use in SubjectAltName otherName
gssExportedName OTHER-NAME ::= {
    GSSExportedName IDENTIFIED BY id-on-gssExportedName
}

-- ===================================================================
-- NFSv4 User@Domain Principal Identity Squashing
-- ===================================================================

-- OID for NFSv4 user@domain principal in otherName
id-on-nfsv4Principal OBJECT IDENTIFIER ::= { id-on TBD }

-- NFSv4 User@Domain Principal Structure
-- In the form RFC 8881 Section 5.9 uses for the owner attribute
NFSv4Principal ::= SEQUENCE {
    principal  UTF8String          -- user@domain string
}

-- For use in SubjectAltName otherName
nfsv4Principal OTHER-NAME ::= {
    NFSv4Principal IDENTIFIED BY id-on-nfsv4Principal
}

END
~~~

# Certificate Examples {#sec-certificate-examples}

This appendix provides examples of X.509 certificates containing the
otherName extensions defined in this document. These examples are
provided in both human-readable notation and hexadecimal DER encoding
to assist implementers in verifying their implementations.

## NFSv4 Principal Example

This example shows a certificate for user "alice" at domain "nfs.example.com":

~~~ asn.1
SubjectAltName ::= SEQUENCE {
    otherName [0] IMPLICIT SEQUENCE {
        type-id OBJECT IDENTIFIER ::= id-on-nfsv4Principal,
        value [0] EXPLICIT NFSv4Principal ::= {
            principal "alice@nfs.example.com"
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 27 A0 25 06 08 2B 06 01 05 05 07 08 XX A0 19
30 17 0C 15 61 6C 69 63 65 40 6E 66 73 2E 65 78
61 6D 70 6C 65 2E 63 6F 6D
~~~

Note: XX represents the TBD value for id-on-nfsv4Principal.

## GSS-API Exported Name Example

This example shows a certificate containing a Kerberos V5 principal
for "bob@EXAMPLE.COM":

~~~ asn.1
SubjectAltName ::= SEQUENCE {
    otherName [0] IMPLICIT SEQUENCE {
        type-id OBJECT IDENTIFIER ::= id-on-gssExportedName,
        value [0] EXPLICIT GSSExportedName ::= {
            nameType 1.2.840.113554.1.2.2,  -- Kerberos V5
            nameValue '04 01 00 0B 06 09 2A 86 48 86 F7 12 01 02 02
                       00 00 00 11 62 6F 62 40 45 58 41 4D 50 4C 45
                       2E 43 4F 4D'H
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 47 A0 45 06 08 2B 06 01 05 05 07 08 YY A0 39
30 37 06 09 2A 86 48 86 F7 12 01 02 02 04 2A 04
01 00 0B 06 09 2A 86 48 86 F7 12 01 02 02 00 00
00 11 62 6F 62 40 45 58 41 4D 50 4C 45 2E 43 4F
4D
~~~

Note: YY represents the TBD value for id-on-gssExportedName.

The nameValue field contains the GSS-API exported name token format
as defined by the Kerberos V5 mechanism. The first four bytes
(04 01 00 0B) are the token ID and length fields defined in
{{Section 3.2 of !RFC2743}}.

## RPC AUTH_SYS Example

This example shows a certificate containing UID 1000, effective GID
1000, and supplementary GIDs 10 and 100:

~~~ asn.1
SubjectAltName ::= SEQUENCE {
    otherName [0] IMPLICIT SEQUENCE {
        type-id OBJECT IDENTIFIER ::= id-on-rpcAuthSys,
        value [0] EXPLICIT RPCAuthSys ::= {
            uid 1000,
            gids { 1000, 10, 100 }
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 20 A0 1E 06 08 2B 06 01 05 05 07 08 ZZ A0 12
30 10 02 02 03 E8 30 0A 02 02 03 E8 02 01 0A 02
01 64
~~~

Note: ZZ represents the TBD value for id-on-rpcAuthSys.

Breaking down the encoding:
- 02 02 03 E8: INTEGER 1000 (UID)
- 30 0A: SEQUENCE OF (GIDs)
  - 02 02 03 E8: INTEGER 1000
  - 02 01 0A: INTEGER 10
  - 02 01 64: INTEGER 100

## Complete Certificate Example

This example shows a minimal self-signed certificate containing an
NFSv4Principal otherName. Line breaks and whitespace have been added
for readability:

~~~
-----BEGIN CERTIFICATE-----
MIICXzCCAcigAwIBAgIUAbCdEfG7KH0FjLbI8N9cJQqQoLwwDQYJKoZIhvcNAQEL
BQAwRDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDzANBgNVBAcM
BklydmluZTEPMA0GA1UECgwGT3JhY2xlMB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEw
MTAwMDAwMFowRDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExDzAN
BgNVBAcMBklydmluZTEPMA0GA1UECgwGT3JhY2xlMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQC7VJTUt9Us8cKjMzEfYyjiWA4R4ypbHqGC0H0+tG3hGbN3MYHa
... [additional base64-encoded certificate data] ...
oxUwEwYDVR0lBAwwCgYIKwYBBQUHAwEwKwYDVR0RBCQwIqAfBggrBgEFBQcIAKAT
DBVhbGljZUBuZnMuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADgYEAk3+...
-----END CERTIFICATE-----
~~~

The SubjectAltName extension in this certificate is encoded at the
position indicated by the bytes following the Extended Key Usage
extension.

## Internationalized Domain Name Example

This example shows an NFSv4Principal with internationalized characters:

~~~ asn.1
SubjectAltName ::= SEQUENCE {
    otherName [0] IMPLICIT SEQUENCE {
        type-id OBJECT IDENTIFIER ::= id-on-nfsv4Principal,
        value [0] EXPLICIT NFSv4Principal ::= {
            principal "用户@例え.jp"    -- UTF-8 encoded user@domain
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 22 A0 20 06 08 2B 06 01 05 05 07 08 XX A0 14
30 12 0C 10 E7 94 A8 E6 88 B7 40 E4 BE 8B E3 81
88 2E 6A 70
~~~

Note: The UTF-8 encoding of the Chinese characters "用户" is
E7 94 A8 E6 88 B7, and the Japanese text "例え" is E4 BE 8B E3 81 88.

## Test Vectors

This section provides test vectors for validating implementations.
Each test case includes the input values, expected ASN.1 structure,
and expected DER encoding.

### Valid NFSv4Principal Test Cases

Test Case 1: Simple ASCII user and domain

Input:

- principal: "bob@example.org"

Expected DER encoding:

~~~
30 21 A0 1F 06 08 2B 06 01 05 05 07 08 XX A0 13
30 11 0C 0F 62 6F 62 40 65 78 61 6D 70 6C 65 2E
6F 72 67
~~~

Test Case 2: User with numbers and domain with subdomain

Input:

- principal: "user123@nfs.lab.example.com"

Expected DER encoding:

~~~
30 2D A0 2B 06 08 2B 06 01 05 05 07 08 XX A0 1F
30 1D 0C 1B 75 73 65 72 31 32 33 40 6E 66 73 2E
6C 61 62 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D
~~~

### Valid RPCAuthSys Test Cases

Test Case 1: Single user, single group

Input:

- uid: 1000
- gids: { 1000 }

Expected DER encoding:

~~~
30 13 A0 11 06 08 2B 06 01 05 05 07 08 ZZ A0 05
30 08 02 02 03 E8 30 04 02 02 03 E8
~~~

Test Case 2: User with empty group list

Input:

- uid: 500
- gids: (empty)

The server supplies the effective GID and supplementary GIDs from its
own user database entry for UID 500.

Expected DER encoding:

~~~
30 0F A0 0D 06 08 2B 06 01 05 05 07 08 ZZ A0 01
30 06 02 02 01 F4 30 00
~~~

Test Case 3: User with maximum 32-bit UID and multiple groups

Input:

- uid: 4294967295
- gids: { 1, 10, 100, 1000 }

Expected DER encoding:

~~~
30 24 A0 22 06 08 2B 06 01 05 05 07 08 ZZ A0 16
30 14 02 05 00 FF FF FF FF 30 0B 02 01 01 02 01
0A 02 01 64 02 02 03 E8
~~~

### Invalid Test Cases

These test cases should be rejected by conforming implementations:

Test Case 1: NFSv4Principal with missing '@' separator

Input (malformed):

- principal: "aliceexample.com" (no '@' character present)

Expected result: Rejection by server (invalid principal string format).
In RFC 8881 a string without '@' signifies that no translation was
available at the sender, so a server has nothing to resolve.

Test Case 2: RPCAuthSys with UID exceeding 32-bit range

Input (malformed):

- uid: 4294967296 (2^32)
- gids: { 1000 }

Expected result: Encoding failure or rejection

Test Case 3: Certificate with multiple identity squashing otherNames

Input (malformed):
SubjectAltName containing both:
- id-on-nfsv4Principal with user "alice@example.com"
- id-on-rpcAuthSys with uid 1000

Expected result: Certificate rejection per Security Considerations

# Acknowledgments
{:numbered="false"}

The authors are grateful to
Jeff Layton,
Greg Marsden,
and
Martin Thomson
for their input and support.

Special thanks to
Area Director
Gorry Fairhurst,
NFSV4 Working Group Chair
Brian Pawlowski,
and
NFSV4 Working Group Secretary
Thomas Haynes
for their guidance and oversight.
