---
title: "Remote Procedure Call Identity Squashing via x.509 Certificate Fields"
abbrev: "SunRPC x.509 Identity Squashing"
category: std

docname: draft-cel-nfsv4-rpc-tls-othername-latest
pi: [toc, sortrefs, symrefs, docmapping]
stand_alone: yes
v: 3

submissiontype: IETF
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
    organization: Oracle Corporation
    abbrev: Oracle
    country: United States of America
    email: chuck.lever@oracle.com

informative:
  SSID:
    target: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    title: Security Identifiers
    author:
      org: Microsoft
    ann: Replace this with a reference to an MS standards doc

venue:
  group: nfsv4
  type: Working Group
  mail: nfsv4@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/nfsv4/
  repo: https://github.com/chucklever/i-d-rpc-tls-othername
  latest: https://chucklever.github.io/i-d-rpc-tls-othername/#go.draft-cel-nfsv4-rpc-tls-othername.html

--- abstract

This document extends RPC-with-TLS, as described in {{!RFC9289}}, so
that a client's x.509 certificate may carry instructions to the RPC
server to execute all RPC transactions from that client as a single
user identity.

--- middle

# Introduction

## Background

The Remote Procedure Call version 2 protocol (RPC, for short) has been
a Proposed Standard for three decades (see {{?RFC5531}} and its
antecedents).
Several important upper layer protocols, such as the family of Network
File System protocols (most recently described in {{?RFC8881}} are based
on RPC.

In 2022, the IETF published {{!RFC9289}}, which specifies a mechanism
by which RPC transactions can be cryptographically protected during
transit. This protection includes maintaining confidentiality and
integrity, and the authentication of the communicating peers.

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
do not have a fixed, well known IP host address or fully qualified DNS name.
The lack of a well known fixed IP host address or fully qualified DNS name
weakens the verification checks that may be done on the client's X.509
certificate by the server.  As such, this extension allows the client to be
restricted to a single user entity on the server, limiting the scope of risk
associated with allowing access to the server.

When a service is running in a dedicated VM or container, it often
runs as a single assigned user identity. Handling this user identity
using Kerberos is problematic, since Kerberos TGTs typically expire
in a matter of hours and the service is typically a long running task.
This extension allows the client to specify the single assigned user
identity to the server in a manner that will not expire for a significant
period of time.

When an RPC server replaces incoming RPC user identities with a single
user identity, for brevity we refer to this as "identity squashing".

## Summary of Proposed Solution

In the interest of enabling the independent creation of interoperating
implementations of RPC identity squashing, this document proposes the
use of the x.509 SubjectAltName otherName field to carry a RPC user
identity.
For these user squashing instructions,
this document establishes a fixed object identifier
carried in the "type-id" part of the otherName field,
and specifies the format of the "value" part of the otherName
field when "type-id" carries the new object identifier.
The document also provides normative guidance on how the "value"
is to be interpreted by RPC servers.

## Open Questions

- Should this be an NFS-only feature, or should it be an RPC-layer
  feature?

- Standardizing a fixed OID is necessary for interoperability, but
  are we required to allocate that OID from a particular arc?

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

This document specifies new uses of the otherName field to carry an
RPC user identity. The receiving system (an RPC server) then
replaces the RPC user, as carried in the RPC header credential and
verifier fields in each RPC request within the TLS session, with the
user identity specified in the certificate used to authenticate that
session.

## Server Processing of otherName Fields

When an RPC server receives a client certificate containing a
SubjectAltName extension, it MUST process the otherName fields as
follows:

1. The server MUST examine all otherName entries in the SubjectAltName
extension.

1. If the server finds an otherName with a type-id that matches one of
the identity squashing OIDs defined in this document (id-on-rpcAuthSys,
id-on-gssExportedName, or id-on-nfsv4Principal), it SHOULD extract
and validate the identity information from that otherName.

1. If multiple identity squashing otherName fields are present in the
same SubjectAltName extension, the server MUST reject the certificate
to avoid ambiguity. See {{sec-security-considerations}} for details.

1. If the server encounters otherName entries with type-id values it does
not recognize, it MUST ignore those entries and continue processing.
This ensures forward compatibility with future extensions.

1. Other types of SubjectAltName entries (dNSName, iPAddress, etc.) are
processed independently and do not affect identity squashing behavior.

The server performs identity squashing only if it successfully validates
an identity squashing otherName field and authorizes its use for the
authenticated TLS peer.

## Interoperability with Non-Supporting Servers

RPC servers that do not implement this specification will not recognize
the otherName OIDs defined in this document. Such servers MUST ignore
unrecognized otherName entries per {{Section 4.2.1.6 of RFC5280}}.
These servers will process RPC requests using the credential information
contained in the RPC header, subject to their normal authentication and
authorization policies. This ensures that clients presenting certificates
with identity squashing otherName fields can interoperate with servers
that do not support this specification, though without identity squashing.

## AUTH_SYS Identities

### otherName OID for AUTH_SYS

{:aside}
> State the Object Identifier to be used to indicate this form
  of RPC user identity

### Format of the otherName Value

{:aside}
> This will be a set of 32-bit integers that specify a numeric UID,
  and a counted list of 32-bit integers that specify numeric GIDs.

## Kerberos V5 Principals

### otherName OID for AUTH_SYS

{:aside}
> State the Object Identifier to be used to indicate this form
  of RPC user identity

### Format of the otherName Value

The otherName value contains a principal name as described in
{{Section 4 of !RFC2743}}.

What you'll need to define in your RFC:

1. Scope & Use Cases: When/why to use GSS principals in certificates
2. Security Considerations: Trust relationships, name canonicalization
3. Mechanism Requirements: What each GSS mechanism must specify for nameValue encoding
4. Name Matching: How to compare two GSSExportedName values
5. IANA Considerations: OID assignment request
6. Examples: Kerberos principals, SPKM, etc.

## NFSv4 User @ Domain String Identities

### otherName OID for String Identities

{:aside}
> State the Object Identifier to be used to indicate this form
  of RPC user identity

### Format of the otherName Value

{:aside}
> Follow recommendations of draft-ietf-nfsv4-internationalization-latest
  to form an internationalized "user@domain" string similar to NFSv4 ID
  map strings.

# Extending This Mechanism

It is possible that in the future, RPC servers might implement other forms
of RPC user identity, such as Windows Security Identifiers (SSIDs) {{SSID}}.
This section describes how standards action can extend the mechanism
specified in this document to accommodate new forms of user identity.

{:aside}
> Provide the base level of general requirements that we will have to
  meet in this document as instructions to future authors. I'm not
  sure yet exactly what those are.

# Implementation Status

{:aside}
> This section is to be removed before publishing this document as an RFC.

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of this
Internet-Draft, and is based on a proposal described in
{{!RFC7942}}. The description of implementations in this section is
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

The security considerations for RPC-with-TLS described in {{Section 8 of RFC9289}}
apply to this specification. In particular, the discussion about certificate
validation, trust anchors, and the establishment of secure TLS sessions remains
relevant.

## Identity Squashing and Authorization

This specification enables a client to request that all RPC operations within a
TLS session be executed under a single user identity specified in the client's
X.509 certificate. This "identity squashing" mechanism has several security
implications:

### Trust in the Certificate Authority

The server MUST carefully consider which Certificate Authorities (CAs) it trusts
to issue certificates containing the otherName extensions defined in this document.
A compromised or malicious CA could issue certificates that allow unauthorized
access to server resources under arbitrary user identities.

Servers SHOULD maintain separate trust anchors for certificates containing
identity squashing otherName fields versus certificates used solely for TLS
peer authentication. This allows administrators to tightly control which CAs
are authorized to assert user identities.

### Authorization Decisions

The presence of an otherName field specifying a user identity does not by itself
grant any authorization. Servers MUST perform their normal authorization checks
to determine whether the requested identity is permitted for the authenticated
TLS peer.

For example, a server might maintain an access control list mapping certificate
subjects or distinguished names to the set of user identities they are permitted
to assume. Only if such authorization succeeds should the server execute RPC
operations under the specified identity.

### Name Canonicalization

#### NFSv4 Principals

When processing NFSv4Principal otherName values, servers MUST apply the same
name canonicalization and domain validation procedures described in
{{Section 5.9 of RFC8881}}. In particular:

- Domain names SHOULD be validated against expected domain suffixes
- Internationalized domain names MUST be properly normalized
- Case-sensitivity rules for usernames and domains MUST be consistently applied

#### GSS-API Exported Names

When processing GSSExportedName otherName values, servers MUST verify that:

- The mechanism OID in the nameType field corresponds to a GSS-API mechanism
  the server supports and trusts
- The nameValue field conforms to the exported name format defined by that
  specific GSS-API mechanism
- The mechanism-specific name validation and canonicalization procedures are
  followed

Servers SHOULD NOT accept exported names from GSS-API mechanisms they do not
fully support, as improper name handling could lead to authorization bypass
vulnerabilities.

#### AUTH_SYS Credentials

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

All RPC operations within a TLS session containing an identity squashing otherName
execute under the same user identity. Servers MUST ensure that session state
cannot be hijacked or transferred between different TLS sessions, as this could
allow an attacker to gain the privileges associated with the squashed identity.

## Revocation

Servers SHOULD support certificate revocation checking (via CRL, OCSP, or similar
mechanisms) for certificates containing identity squashing otherName fields.
Since these certificates grant user-level access to server resources, timely
revocation is critical when a certificate is compromised or a user's access
should be terminated.

## Privacy Considerations

The otherName fields defined in this specification reveal user identity information
in the client's X.509 certificate. This information is transmitted during the TLS
handshake and may be visible to network observers if the handshake is not properly
protected.

While TLS 1.3 encrypts most of the handshake including certificates, earlier TLS
versions may expose this information. Deployments concerned about privacy SHOULD
use TLS 1.3 or later.

## Multiple Identity Formats

Implementations MUST NOT allow multiple identity squashing otherName fields to be
present simultaneously in the same SubjectAltName extension. If multiple such
fields are present (e.g., both RPCAuthSys and NFSv4Principal), the server MUST
reject the certificate to avoid ambiguity about which identity should be used.

# IANA Considerations {#sec-iana-considerations}

## SMI Security for PKIX Module Identifier

IANA is requested to assign three object identifiers for the ASN.1 modules
specified in this document in the "SMI Security for PKIX Module Identifier"
registry (1.3.6.1.5.5.7.0):

| Decimal | Description                      | References  |
|:--------|:---------------------------------|:------------|
| TBD1    | id-mod-rpc-auth-sys              | RFC-TBD     |
| TBD2    | id-mod-gss-exported-name         | RFC-TBD     |
| TBD3    | id-mod-nfsv4-principal           | RFC-TBD     |

## SMI Security for PKIX Other Name Forms

IANA is requested to assign three object identifiers for the otherName
types specified in this document in the "SMI Security for PKIX Other
Name Forms" registry (1.3.6.1.5.5.7.8):

| Decimal | Description                      | References  |
|:--------|:---------------------------------|:------------|
| TBD4    | id-on-rpcAuthSys                 | RFC-TBD     |
| TBD5    | id-on-gssExportedName            | RFC-TBD     |
| TBD6    | id-on-nfsv4Principal             | RFC-TBD     |

These otherName identifiers are used in the SubjectAltName extension
of X.509 certificates to carry RPC user identity information for the
purpose of identity squashing as described in this document.

"RFC-TBD" is to be replaced with the actual RFC number when this
document is published.

--- back

# ASN.1 Modules

The following ASN.1 modules normatively specify the structure of
the new otherName values described in this document.
This specification uses the ASN.1 definitions from
{{?RFC5912}} with the 2002 ASN.1 notation used in that document.
{{RFC5912}} updates normative documents using older ASN.1 notation.

## The RpcAuthSysUser

~~~ asn.1
RPCAuthSysCertExtn
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-rpc-auth-sys(TBD) }

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

-- OID for RPC AUTH_SYS credentials in otherName
id-on-rpcAuthSys OBJECT IDENTIFIER ::= { id-on TBD }

-- RPC AUTH_SYS Credentials Structure
-- UID and GID list as used in RPC AUTH_SYS authentication flavor
-- See RFC 5531 (ONC RPC) and related specifications
RPCAuthSys ::= SEQUENCE {
    uid        INTEGER (0..4294967295),  -- 32-bit UID
    gids       SEQUENCE OF INTEGER (0..4294967295)  -- List of 32-bit GIDs
}

-- For use in SubjectAltName otherName
rpcAuthSys OTHER-NAME ::= {
    RPCAuthSys IDENTIFIED BY id-on-rpcAuthSys
}

END
~~~

## The RpcGssUser

~~~ asn.1
GSSAPIPrincipalCertExtn
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-gss-exported-name(TBD) }

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

END
~~~

## The RpcNfsv4User

~~~ asn.1
NFSv4PrincipalCertExtn
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-nfsv4-principal(TBD) }

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

-- OID for NFSv4 user@domain principal in otherName
id-on-nfsv4Principal OBJECT IDENTIFIER ::= { id-on TBD }

-- NFSv4 User@Domain Principal Structure
-- As defined in RFC 8881 Section 5.9
NFSv4Principal ::= SEQUENCE {
    user       UTF8String,
    atSign     IA5String (SIZE (1)) (FROM ("@")),
    domain     UTF8String  -- Supports internationalized domain names
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
            user "alice",
            atSign "@",
            domain "nfs.example.com"
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 2B A0 29 06 08 2B 06 01 05 05 07 08 XX A0 1D
0C 05 61 6C 69 63 65 13 01 40 0C 0F 6E 66 73 2E
65 78 61 6D 70 6C 65 2E 63 6F 6D
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
{{Section 3.2 of RFC2743}}.

## RPC AUTH_SYS Example

This example shows a certificate containing UID 1000 and GIDs
1000, 10, and 100:

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
            user "用户",        -- Chinese characters for "user"
            atSign "@",
            domain "例え.jp"    -- Japanese IDN
        }
    }
}
~~~

DER encoding (hexadecimal):

~~~
30 2D A0 2B 06 08 2B 06 01 05 05 07 08 XX A0 1F
0C 06 E7 94 A8 E6 88 B7 13 01 40 0C 0C E4 BE 8B
E3 81 88 2E 6A 70
~~~

Note: The UTF-8 encoding of the Chinese characters "用户" is
E7 94 A8 E6 88 B7, and the Japanese text "例え" is E4 BE 8B E3 81 88.

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
NFSV4 Working Group Chairs
Brian Pawlowski
and
Christopher Inacio,
and
NFSV4 Working Group Secretary
Thomas Haynes
for their guidance and oversight.
