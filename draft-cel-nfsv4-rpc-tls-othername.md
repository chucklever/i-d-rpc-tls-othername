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

This document specifies new uses of the otherName field to carry an
RPC user identity. The receiving system (an RPC server) then
replaces the RPC user, as carried in the RPC header credential and
verifier fields in each RPC request within the TLS session, with the
user identity specified in the certificate used to authenticate that
session.

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

# Security Considerations

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

~~~ ASN.1
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

~~~ ASN.1
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

~~~ ASN.1
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
