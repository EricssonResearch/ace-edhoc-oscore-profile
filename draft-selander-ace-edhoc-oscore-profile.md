---
coding: utf-8

title: Ephemeral Diffie-Hellman Over COSE (EDHOC) and Object Security for Constrained Environments (OSCORE) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: CoAP-EDHOC-OSCORE
docname: draft-selander-ace-edhoc-oscore-profile-latest
category: std

ipr: trust200902
area: Security
workgroup: ACE Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
-
    ins: G. Selander
    name: Göran Selander
    org: Ericsson
    email: goran.selander@ericsson.com
-
    ins: J. Preuß Mattsson
    name: John Preuß Mattsson
    org: Ericsson
    email: john.mattsson@ericsson.com

-
    ins: M. Tiloca
    name: Marco Tiloca
    org: RISE
    email: marco.tiloca@ri.se

-
    ins: R. Höglund
    name: Rikard Höglund
    org: RISE
    email: rikard.hoglund@ri.se

normative:
  RFC2119:
  RFC8174:
  RFC6347:
  RFC6749:
  RFC7250:
  RFC7251:
  RFC7252:
  RFC7519:
  RFC7800:
  RFC7925:
  RFC8126:
  RFC8152:
  RFC8392:
  RFC8422:
  RFC8613:
  RFC8747:
  RFC8949:
  RFC9200:
  RFC9201:
  I-D.ietf-lake-edhoc:
  I-D.ietf-core-oscore-edhoc:
  I-D.ietf-cose-x509:
  I-D.ietf-cose-cbor-encoded-cert:

informative:
  RFC5869:
  RFC7662:
  RFC7748:
  RFC8032:
  RFC8446:
  RFC8610:
  RFC9147:
  I-D.ietf-ace-oscore-profile:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework.
It utilizes Ephemeral Diffie-Hellman Over COSE (EDHOC) for mutual authentication between OAuth 2.0 Client and Resource Server and binds an authentication credential of the Client to an OAuth 2.0 Access Token.
EDHOC also establishes an OSCORE security context used to secure communication with protected resources according to the authorization information indicated in the access token.
A resource-constrained server can use this profile to delegate management of authorization information to a trusted host with less severe limitations regarding processing power and memory.

--- middle


# Introduction

This specification defines the `coap_edhoc_oscore` profile of the ACE framework {{RFC9200}}.
This profile addresses a "zero-touch" constrained setting where trusted operations can be performed with low overhead without endpoint specific configurations.

In this profile the client (C) can access protected resources hosted at the resource server (RS) with the use of an access token issued by a trusted authorization server (AS) which associates access rights to an authentication credential of C.
The authentication credential can be a raw public key of C, e.g., encoded as a CWT Claims Set (CCS, {{RFC8392}}), or a public key certificate, e.g. encoded as an X.509 certificate or CBOR encoded X.509 certificate (C509, {{I-D.ietf-cose-cbor-encoded-cert}}), or other data structure containing or uniquely referencing the public key of C.

C and RS use the Constrained Application Protocol (CoAP) {{RFC7252}} to communicate, and Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} to protect the communication, like in the `coap_oscore` profile of ACE {{I-D.ietf-ace-oscore-profile}}.
But instead of associating the access rights to a symmetric key of C, as in the `coap_oscore` profile, the access rights in this profile are associated to an authentication credential of C, and uses Ephemeral Diffie-Hellman Over COSE (EDHOC) to prove possession of the corresponding private key.

RS obtains the access token for C (different options are possible) and they run the EDHOC protocol for mutual authentication.
RS matches the authentication credential associated to the access token against the authentication credential used by the other endpoint.
If relevant verifications are successful, RS concludes that the other endpoint has the associated access rights, and derives the corresponding OSCORE security context.
The processing of requests for specific protected resources is identical to the `coap_oscore` profile.

In this process C and RS need to access each other's authentication credentials.
The ACE protocol establishes what those authentication credentials are and may transport the actual credentials.
If the actual credentials are pre-provisioned or can be obtained over less constrained links then it sufficies that ACE provides a unique reference such as a certificate hash (e.g., using x5t, see {{I-D.ietf-cose-x509}}).
This is in the same spirit as EDHOC, where the authentication credentials may be transported or referenced in the ID_CRED_x message fields, see {{I-D.ietf-lake-edhoc}}.

Generally, the AS and RS are likely to have trusted access to each other's credentials since AS acts on behalf of RS, by the trust model of ACE.
AS needs also to have some information about C to verify from whom the request is coming and for what it is authorized, but this may potentially be obtained dynamically as part of the request.


As recommended in Section 5.8 of {{RFC9200}}, this
specification uses CBOR Web Tokens (CWT) to convey claims within an access
token issued by the AS.

Marco's comments:

   * New "CWT Confirmation Methods" are registered (e.g., "x5t", "xchain", ..."), basically to cover the types of ID_CRED_X supported in EDHOC.

   * The Client receives the Token Response from the AS, and takes the value of 'rs_cnf' as ID_CRED_R.
   Depending on the specific type of 'rs_cnf', the RS' authentication credential here can be pointed by reference or transported by value (what is possible and most efficient to do).

   * The RS receives the Token from the Client, and takes the value of the 'cnf' claim as ID_CRED_I.
   Depending on the specific type of 'cnf', the Client's authentication credential here can be pointed by reference or transported by value (what is possible and most efficient to do).

  * 'req_cnf' can be transferred by reference; 'cnf' and 'rs_cnf' has to be transferred by value.

   * When the Client initially runs EDHOC with the AS (before sending the Token request), both Client and AS can indicate their own authentication credential by reference in ID_CRED_X.

   * Following the expiration of the first token, if the client asks for a new one: 'req_cnf' can be transferred by reference; 'cnf' and 'rs_cnf' can also be transferred by reference. Then EDHOC also uses only transferring by reference.



## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

Readers are expected to be familiar with security for CoAP {{RFC7252}} based on OSCORE {{RFC8613}} and EDHOC {{I-D.ietf-lake-edhoc}}.
Readers are also expected to be familiar with the terms and concepts of the ACE framework
described in {{RFC9200}} and in {{RFC9201}}.

The authorization information (authz-info) resource refers to the authorization information endpoint as specified in {{RFC9200}}.
The term `claim` is used in this document with the same semantics
as in {{RFC9200}}, i.e., it denotes information carried
in the access token or returned from introspection.

<!-- Add terminology from RFC-to-be 9203 -->

# Protocol Overview {#overview}

This section gives an overview of how to use the ACE framework {{RFC9200}} together with the EDHOC authentication protocol to generate an OSCORE security context with associated authorization information.

The RS maintains a collection of authentication credentials with associated OSCORE security context and authorization information for all the clients that it is communicating with. The authorization information is maintained as policy that is used as input to processing requests from those clients.

This profile requires C to retrieve an access token from the AS for the resource it wants to access on an RS, by sending an access token request to the token endpoint, as specified in Section 5.8 of {{RFC9200}}. The access token request and response MUST be confidentiality protected and ensure authenticity. The use of EDHOC and OSCORE between the client and AS is RECOMMENDED in this profile, to reduce the number of libraries C has to support, but other protocols fulfilling the security requirements defined in Section 5 of {{RFC9200}} MAY alternatively be used, such as TLS {{RFC8446}} or DTLS {{RFC9147}}.

Once C has retrieved the access token, it posts the token to the RS, either using the authz-info endpoint and mechanisms specified in Section 5.8 of {{RFC9200}} and Content-Format = application/ace+cbor, or with EAD_1 of EDHOC message_1 using the External Authorization Data (EAD) mechanism of {{I-D.ietf-lake-edhoc}} as further detailed in this document.

In the former case, if the access token is valid, the RS responds to the request with a 2.01 (Created) response with Content-Format = application/ace+cbor. In this case and in the latter case above, C and RS mutually authenticate using EDHOC and if successful derive an OSCORE security context. The RS associates C with the access rights of the received token.

 When using this profile, the communication with the authz-info endpoint is not protected, except for the update of access rights.

C gains authorized access to protected resources on RS as long as the access token is valid. The OSCORE security context is discarded when a token (whether the same or a different one) is used to successfully derive a new security context for that client, either by using the EDHOC-KeyUpdate procedure or re-running the EDHOC protocol.

 After the whole message exchange has taken place, the client can contact the AS to request an update of its access rights, sending a similar request to the token endpoint that also includes an identifier so that the AS can find the correct data it has previously shared with the client. This specific identifier, encoded as a byte string, is assigned by the AS to be unique in the sets of granted client access rights.

An overview of the protocol flow for the `coap_edhoc_oscore` profile is given in {{protocol-overview}}. The names of messages coincide with those of {{RFC9200}} when applicable.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   |                            |                     |
   | <== Mutual authentication and secure channel ==> |
   |                            |                     |
   | ----- POST /token  ----------------------------> |
   |                            |                     |
   | <---------------------------- Access Token ----- |
   |                           + Access Information   |
   |                            |                     |
   | [--- POST /authz-info -->] |                     |
   |       (access_token)       |                     |
   |                            |                     |
   | [<---- 2.01 Created  ----] |                     |
   |                            |                     |
   | <========= EDHOC ========> |                     |
   |  OSCORE Sec Context deriv. |                     |
   |                            |                     |
Sec Context storage/    Sec Context storage/          |
   |                            |                     |
   | ---- OSCORE Request -----> |                     |
   |                            |                     |
   | <--- OSCORE Response ----- |                     |
   |                            |                     |
   |           ...              |                     |

~~~~~~~~~~~~~~~~~~~~~~~
{: #protocol-overview title="Protocol Overview"}



NOTE: The rest of the draft is a copy of draft-ietf-ace-dtls-authorize. The mode of writing has been to compare the text below with draft-ietf-ace-oscore-profile (for which there is no Markdown document) and selected relevant parts from respective drafts.


# Protocol Flow

The following sections specify how CoAP is used to interchange
access-related data between the resource server, the client and the
authorization server so that the authorization server can provide the
client and the resource server with sufficient information to
establish a secure channel, and convey authorization information
specific for this communication relationship to the resource server.

{{C-AS-comm}} describes how the communication between the client (C) and
the authorization server (AS) must be secured.
Depending on the used CoAP security mode (see also
Section 9 of {{RFC7252}},
the Client-to-AS request, AS-to-Client response and DTLS session
establishment carry slightly different information. {{rpk-mode}}
addresses the use of raw public keys.

## Communication Between the Client and the Authorization Server {#C-AS-comm}

To retrieve an access token for the resource that the client wants to
access, the client requests an access token from the authorization
server. Before the client can request the access token, the client and
the authorization server MUST establish
a secure communication channel. This profile assumes that the keying
material to secure this communication channel has securely been obtained
either by manual configuration or in an automated provisioning process.
The following requirements in alignment with Section 6.5 of
{{RFC9200}} therefore must be met:

* The client MUST securely have obtained keying material to communicate
  with the authorization server.
* Furthermore, the client MUST verify that the authorization server is
  authorized to provide access tokens (including authorization
  information) about the resource server to the client, and that
  this authorization information about the authorization server is still valid.
* Also, the authorization server MUST securely have obtained keying
  material for the client, and obtained authorization rules approved
  by the resource owner (RO) concerning the client and the resource
  server that relate to this keying material.

The client and the authorization server MUST use their respective
keying material for all exchanged messages. How the security
association between the client and the authorization server is
bootstrapped is not part of this document. The client and the
authorization server must ensure the confidentiality, integrity and
authenticity of all exchanged messages within the ACE protocol.

{{as-commsec}} specifies how communication with the authorization server is secured.


## Raw Public Key Mode {#rpk-mode}

When the client uses raw public key authentication, the procedure is as
described in the following.

### Access Token Retrieval from the Authorization Server

After the client and the authorization server mutually authenticated each other and validated each
other's authorization, the client sends a token request to the authorization server's token endpoint.
The client MUST add a `req_cnf` object carrying either its raw public key
or a unique identifier for a public key that it has previously made
known to the authorization server. It is RECOMMENDED that
the client uses DTLS with the same keying material to secure the
communication with the authorization server, proving possession of the key
as part of the token request. Other mechanisms for proving possession of
the key may be defined in the future.

An example access token request from the client to the authorization
server is depicted in {{rpk-authorization-message-example}}.

~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: application/ace+cbor
   Payload:
   {
     grant_type : client_credentials,
     audience   : "tempSensor4711",
     req_cnf    : {
       COSE_Key : {
         kty : EC2,
         crv : P-256,
         x   : h'e866c35f4c3c81bb96a1...',
         y   : h'2e25556be097c8778a20...'
       }
     }
   }
~~~~~~~~~~
{: #rpk-authorization-message-example title="Access Token Request Example for RPK Mode"}

The example shows an access token request for the resource identified
by the string "tempSensor4711" on the authorization server
using a raw public key.

The authorization server MUST check if the client that it communicates
with is associated with the RPK in the `req_cnf` parameter before
issuing an access token to it.  If the authorization server determines
that the request is to be authorized according to the respective
authorization rules, it generates an access token response for the
client. The access token MUST be bound to the RPK of the client by
means of the `cnf` claim.

The response MUST contain an `ace_profile` parameter if
the `ace_profile` parameter in the request is empty, and MAY contain
this parameter otherwise (see Section 5.8.2 of
{{RFC9200}}). This parameter is set to `coap_dtls` to
indicate that this profile MUST be used for communication between the
client and the resource server. The response
also contains an access token with information for the resource server
about the client's public key. The authorization server MUST return in
its response the parameter `rs_cnf` unless it is certain that the
client already knows the public key of the resource server.  The
authorization server MUST ascertain that the RPK specified in `rs_cnf`
belongs to the resource server that the client wants to communicate
with. The authorization server MUST protect the integrity of the
access token such that the resource server can detect unauthorized
changes.  If the access token contains confidential data, the
authorization server MUST also protect the confidentiality of the
access token.

The client MUST ascertain that the access token response belongs to a certain
previously sent access token request, as the request may specify the
resource server with which the client wants to communicate.

An example access token response from the authorization server to the client
is depicted in {{rpk-authorization-response-example}}. Here, the
contents of the `access_token` claim have been truncated to improve
readability. The response comprises access information for the client
that contains the server's public key in the `rs_cnf` parameter.
Caching proxies process the Max-Age option in the CoAP response which
has a default value of 60 seconds (Section 5.6.1 of [RFC7252]).
The authorization server SHOULD
adjust the Max-Age option such that it does not exceed the
`expires_in` parameter to avoid stale responses.

~~~~~~~~~~
   2.01 Created
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
     access_token : b64'SlAV32hkKG...
      (remainder of CWT omitted for brevity;
      CWT contains the client's RPK in the cnf claim)',
     expires_in : 3600,
     rs_cnf     : {
       COSE_Key : {
         kty : EC2,
         crv : P-256,
         x   : h'd7cc072de2205bdc1537...',
         y   : h'f95e1d4b851a2cc80fff...'
       }
     }
   }
~~~~~~~~~~
{: #rpk-authorization-response-example title="Access Token Response Example for RPK Mode"}

### DTLS Channel Setup Between Client and Resource Server {#rpk-dtls-channel}

Before the client initiates the DTLS handshake with the resource
server, the client MUST send a `POST` request containing the obtained
access token to the authz-info resource hosted by the resource
server. After the client receives a confirmation that the resource
server has accepted the access token, it proceeds to establish a
new DTLS channel with the resource server.  The client MUST use its
correct public key in the DTLS handshake. If the authorization server
has specified a `cnf` field in the access token response, the client
MUST use this key. Otherwise, the client MUST use the public key that
it specified in the `req_cnf` of the access token request. The client
MUST specify this public key in the SubjectPublicKeyInfo structure of
the DTLS handshake as described in [RFC7250].

If the client does not have the keying material belonging to the
public key, the client MAY try to send an access token request to the
AS where it specifies its public key in the `req_cnf` parameter. If
the AS still specifies a public key in the response that the client
does not have, the client SHOULD re-register with the authorization
server to establish a new client public key. This process is out of
scope for this document.

To be consistent with {{RFC7252}}, which allows for shortened MAC tags
in constrained environments,
an implementation that supports the RPK mode of this profile MUST at
least support the cipher suite
TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_CCM\_8 {{RFC7251}}.
As discussed in {{RFC7748}}, new ECC
  curves have been defined recently that are considered superior to
  the so-called NIST curves. Implementations of this profile therefore
  MUST implement support for curve25519 (cf. {{RFC8032}}, {{RFC8422}})
  as this curve said to be efficient and less dangerous
  regarding implementation errors than the secp256r1 curve mandated in
  {{RFC7252}}.

The resource server MUST check if the access token is still valid, if
the resource server is the intended destination (i.e., the audience)
of the token, and if the token was issued by an authorized
authorization server (see also section 5.10.1.1 of
{{RFC9200}}).
The access token is constructed by the
authorization server such that the resource server can associate the
access token with the Client's public key.  The `cnf` claim MUST
contain either the client's RPK or, if the key is already known by the
resource server (e.g., from previous communication), a reference to
this key. If the authorization server has no certain knowledge that
the Client's key is already known to the resource server, the Client's
public key MUST be included in the access token's `cnf` parameter. If
CBOR web tokens {{RFC8392}} are used (as recommended in
{{RFC9200}}), keys MUST be encoded as specified in
{{RFC8747}}. A resource server MUST have the capacity to store one
access token for every proof-of-possession key of every authorized client.

The raw public key used in the DTLS handshake with the client MUST
belong to the resource server. If the resource server has several raw
public keys, it needs to determine which key to use. The authorization
server can help with this decision by including a `cnf` parameter in
the access token that is associated with this communication.  In this
case, the resource server MUST use the information from the `cnf`
field to select the proper keying material.

Thus, the handshake only finishes if the client and the resource
server are able to use their respective keying material.

## Resource Access

Once a DTLS channel has been established as described in {{rpk-mode}}
 the client is authorized to access
resources covered by the access token it has uploaded to the
authz-info resource hosted by the resource server.

With the successful establishment of the DTLS channel, the client and
the resource server have proven that they can use their respective
keying material. An access token that is bound to the client's keying
material is associated with the channel. According to Section 5.10.1 of
{{RFC9200}}, there should be only one access token
for each client. New access tokens issued by the authorization server
SHOULD replace previously issued access tokens for the
respective client. The resource server therefore needs a common
understanding with the authorization server how access tokens are
ordered. The authorization server may, e.g., specify a `cti` claim for
the access token (see Section 5.9.4 of {{RFC9200}}) to
employ a strict order.

Any request that the resource server receives on a DTLS channel that
is tied to an access token via its keying material
MUST be checked against the authorization rules that can be determined
with the access token. The resource server
MUST check for every request if the access token is still valid.
If the token has expired, the resource server MUST remove it.
Incoming CoAP requests that are not authorized with respect
to any access token that is associated with the client MUST be
rejected by the resource server with 4.01 response. The response
SHOULD include AS Request Creation Hints as described in
Section 5.2 of {{RFC9200}}.

The resource server MUST NOT accept an incoming CoAP request as
authorized if any of the following fails:

1. The message was received on a secure channel that has been
   established using the procedure defined in this document.
1. The authorization information tied to the sending client is valid.
1. The request is destined for the resource server.
1. The resource URI specified in the request is covered by the
   authorization information.
1. The request method is an authorized action on the resource with
   respect to the authorization information.

Incoming CoAP requests received on a secure DTLS channel that are not
thus authorized MUST be
rejected according to Section 5.10.1.1 of {{RFC9200}}

1. with response code 4.03 (Forbidden) when the resource URI specified
   in the request is not covered by the authorization information, and
1. with response code 4.05 (Method Not Allowed) when the resource URI
   specified in the request covered by the authorization information but
   not the requested action.

The client MUST ascertain that its keying material is still valid
before sending a request or processing a response. If the client
recently has updated the access token (see {{update}}), it must be
prepared that its request is still handled according to the previous
authorization rules as there is no strict ordering between access
token uploads and resource access messages. See also
{{multiple-access-tokens}} for a discussion of access token
processing.

If the client gets an error response
containing AS Request Creation Hints (cf.  Section 5.3 of {{RFC9200}}
as response to its requests, it SHOULD request a new access token from
the authorization server in order to continue communication with the
resource server.

Unauthorized requests that have been received over a DTLS session
SHOULD be treated as non-fatal by the resource server, i.e., the DTLS
session SHOULD be kept alive until the associated access token has
expired.

# Dynamic Update of Authorization Information {#update}

Resource servers must only use a new access token to update the
authorization information for a DTLS session if the keying material
that is bound to the token is the same that was used in the DTLS
handshake. By associating the access tokens with the identifier of an
existing DTLS session, the authorization information can be updated
without changing the cryptographic keys for the DTLS communication
between the client and the resource server, i.e. an existing session
can be used with updated permissions.

The client can therefore update the authorization information stored at the
resource server at any time without changing an established DTLS
session. To do so, the client requests a
new access token from the authorization server
for the intended action on the respective resource
and uploads this access token to the authz-info resource on the
resource server.

{{update-overview}} depicts the message flow where the client requests
a new access token after a security association between the client and
the resource server has been established using this protocol. If the
client wants to update the authorization information, the token
request MUST specify the key identifier of the proof-of-possession key
used for the existing DTLS channel between the client and the resource
server in the `kid` parameter of the Client-to-AS request. The
authorization server MUST verify that the specified `kid` denotes a
valid verifier for a proof-of-possession token that has previously
been issued to the requesting client. Otherwise, the Client-to-AS
request MUST be declined with the error code `unsupported_pop_key` as
defined in Section 5.8.3 of {{RFC9200}}.

When the authorization server issues a new access token to update
existing authorization information, it MUST include the specified `kid`
parameter in this access token. A resource server MUST replace the
authorization information of any existing DTLS session that is identified
by this key identifier with the updated authorization information.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                   AS
   | <===== DTLS channel =====> |                     |
   |        + Access Token      |                     |
   |                            |                     |
   | --- Token Request  ----------------------------> |
   |                            |                     |
   | <---------------------------- New Access Token - |
   |                           + Access Information   |
   |                            |                     |
   | --- Update /authz-info --> |                     |
   |     New Access Token       |                     |
   |                            |                     |
   | == Authorized Request ===> |                     |
   |                            |                     |
   | <=== Protected Resource == |                     |

~~~~~~~~~~~~~~~~~~~~~~~
{: #update-overview title="Overview of Dynamic Update Operation"}

# Token Expiration {#teardown}

The resource server MUST delete access tokens that are no longer
valid.  DTLS associations that have been setup in accordance with
this profile are always tied to specific tokens (which may be
exchanged with a dynamic update as described in Section 4). As tokens
may become invalid at any time (e.g., because they have expired), the
association may become useless at some point.  A resource server therefore
MUST terminate existing DTLS association after the last access token
associated with this association has expired.

As specified in Section 5.10.3 of {{RFC9200}},
the resource server MUST notify the client with an error response with
code 4.01 (Unauthorized) for any long running request before
terminating the association.

# Secure Communication with an Authorization Server {#as-commsec}

As specified in the ACE framework (Sections 5.8 and 5.9 of
{{RFC9200}}), the requesting entity (the resource
server and/or the client) and the authorization server communicate via
the token endpoint or introspection endpoint.  The use of CoAP and
DTLS for this communication is RECOMMENDED in this profile. Other
protocols fulfilling the security requirements defined in Section 5
of {{RFC9200}} MAY be used instead.

How credentials (e.g., RPK, X.509 cert) for using DTLS with the
authorization server are established is out of scope for this profile.

If other means of securing the communication with the authorization
server are used, the communication security requirements from Section
6.2 of {{RFC9200}} remain applicable.

# EDHOC Application Profile Parameters # {#key-edhoc-params}

This specification defines a number of EDHOC application profile parameters that can be transported in the 'edhoc_params' parameter of a Token Response to the Client, or in the 'edhoc_params' claim of an access token.

In the former case, when the response payload is encoded as a CBOR map, the response MUST use the Content-Format "application/ace+cbor" defined in {{RFC9200}}.

The table below summarizes them, and specifies the CBOR value to use as abbreviation instead of the full descriptive name.

~~~~~~~~~~~
+-------+-------+------+----------+-------------+---------------+
| Name  | CBOR  | CBOR | Registry | Description | Specification |
|       | Value | Type |          |             |               |
+-------+-------+------+----------+-------------+---------------+
| TBD   | TBD   | TBD  | TBD      | TBD         |               |
+-------+-------+------+----------+-------------+---------------+
~~~~~~~~~~~
{: #fig-cbor-key-edhoc-params title="CBOR abbreviations for the EDHOC application profile parameters" artwork-align="center"}

\[ TODO: fill the table \]

# Security Considerations

This document specifies a profile for the Authentication and
Authorization for Constrained Environments (ACE) framework
{{RFC9200}}. As it follows this framework's general
approach, the general security considerations from Section
6 of {{RFC9200}} also apply to this profile.

The authorization server must ascertain that the keying material for
the client that it provides to the resource server actually is
associated with this client.  Malicious clients may hand over access
tokens containing their own access permissions to other entities. This
problem cannot be completely eliminated. Nevertheless, in RPK mode it
should not be possible for clients to request access tokens for
arbitrary public keys: if the client can cause the authorization
server to issue a token for a public key without proving possession of
the corresponding private key, this allows for identity misbinding
attacks where the issued token is usable by an entity other than the
intended one.  The authorization server therefore at some point needs
to validate that the client can actually use the private key
corresponding to the client's public key.

Constrained devices that use DTLS {{RFC6347}} are inherently
vulnerable to Denial of Service (DoS) attacks as the handshake
protocol requires creation of internal state within the device.  This
is specifically of concern where an adversary is able to intercept the
initial cookie exchange and interject forged messages with a valid
cookie to continue with the handshake. A similar issue exists with the
unprotected authorization information endpoint when the resource
server needs to keep valid access tokens for a long time. Adversaries
could fill up the constrained resource server's internal storage for a
very long time with interjected or otherwise retrieved valid access
tokens.  To mitigate against this, the resource server should set a
time boundary until an access token that has not been used until then
will be deleted.

The protection of access tokens that are stored in the authorization
information endpoint depends on the keying material that is used between
the authorization server and the resource server: The resource server
must ensure that it processes only access tokens that are (encrypted
and) integrity-protected by an authorization server that is authorized
to provide access tokens for the resource server.

## Reuse of Existing Sessions

To avoid the overhead of a repeated DTLS handshake, {{RFC7925}}
recommends session resumption {{RFC8446}} to reuse session state from
an earlier DTLS association and thus requires client side
implementation.  In this specification, the DTLS session is subject to
the authorization rules denoted by the access token that was used for
the initial setup of the DTLS association. Enabling session resumption
would require the server to transfer the authorization information
with the session state in an encrypted SessionTicket to the
client. Assuming that the server uses long-lived keying material, this
could open up attacks due to the lack of forward secrecy. Moreover,
using this mechanism, a client can resume a DTLS session without
proving the possession of the PoP key again. Therefore, session
resumption should be used only in combination with reasonably
short-lived PoP keys.

Since renegotiation of DTLS associations is prone to attacks as well,
{{RFC7925}} requires clients to decline any renegotiation attempt. A
server that wants to initiate re-keying therefore SHOULD periodically
force a full handshake.

## Multiple Access Tokens

Developers SHOULD avoid using multiple access tokens for a
client (see also section 5.10.1 of {{RFC9200}}).

Even when a single access token per client is used, an attacker could
compromise the dynamic update mechanism for existing DTLS connections
by delaying or reordering packets destined for the authz-info
endpoint. Thus, the order in which operations occur at the resource
server (and thus which authorization info is used to process a given
client request) cannot be guaranteed.  Especially in the presence of
later-issued access tokens that reduce the client's permissions from
the initial access token, it is impossible to guarantee that the
reduction in authorization will take effect prior to the expiration of
the original token.

## Out-of-Band Configuration

To communicate securely, the authorization server, the client and the
resource server require certain information that must be exchanged
outside the protocol flow described in this document. The
authorization server must have obtained authorization information
concerning the client and the resource server that is approved by the
resource owner as well as corresponding keying material. The resource
server must have received authorization information approved by the
resource owner concerning its authorization managers and the
respective keying material. The client must have obtained
authorization information concerning the authorization server approved
by its owner as well as the corresponding keying material. Also, the
client's owner must have approved of the client's communication with
the resource server. The client and the authorization server must have
obtained a common understanding how this resource server is identified
to ensure that the client obtains access token and keying material for
the correct resource server. If the client is provided with a raw
public key for the resource server, it must be ascertained to which
resource server (which identifier and authorization information) the
key is associated.  All authorization information and keying material
must be kept up to date.

# Privacy Considerations

This privacy considerations from Section
7 of the {{RFC9200}} apply also to this profile.

An unprotected response to an unauthorized request may disclose
information about the resource server and/or its existing relationship
with the client. It is advisable to include as little information as
possible in an unencrypted response. When a DTLS session between an authenticated
client and the resource server already exists, more detailed
information MAY be included with an error response to provide the
client with sufficient information to react on that particular error.

Also, unprotected requests to the resource server may reveal
information about the client, e.g., which resources the client
attempts to request or the data that the client wants to provide to
the resource server. The client SHOULD NOT send confidential data in
an unprotected request.

Note that some information might still leak after DTLS session is
established, due to observable message sizes, the source, and the
destination addresses.

# IANA Considerations

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with
the RFC number of this specification and delete this paragraph.

## ACE OAuth Profile Registry ## {#iana-ace-oauth-profile}

IANA is asked to add the following entry to the "ACE OAuth Profile"
Registry following the procedure specified in {{RFC9200}}.

* Profile name: coap_edhoc_oscore
* Profile Description: Profile for delegating client authentication and
authorization in a constrained environment by establishing an OSCORE Security Context {{RFC8613}} between resource-constrained nodes, through the execution of the authenticated key establishment protocol EDHOC {{I-D.ietf-core-oscore-edhoc}}.
* Profile ID:  TBD (value between 1 and 255)
* Change Controller: IESG
* Reference:  {{&SELF}}

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entries to the "OAuth Parameters" registry.

* Name: "edhoc_params"
* Parameter Usage Location: token response
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Name: "token_uploaded"
* Parameter Usage Location: token response
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-token-cbor-mappings}

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" following the procedure specified in {{RFC9200}}.

* Name: "edhoc_params"
* CBOR Key: TBD
* Value Type: map
* Specification Document(s): {{&SELF}}

&nbsp;

* Name: "token_uploaded"
* CBOR Key: TBD
* Value Type: simple value "true" / simple type "false"
* Specification Document(s): {{&SELF}}

## JSON Web Token Claims Registry ## {#iana-token-json-claims}

IANA is asked to add the following entries to the "JSON Web Token Claims" registry following the procedure specified in {{RFC7519}}.

*  Claim Name: "edhoc_params"
*  Claim Description: Parameters of the EDHOC application profile to use
*  Change Controller: IETF
*  Reference: {{&SELF}}

## CBOR Web Token Claims Registry ## {#iana-token-cwt-claims}

IANA is asked to add the following entries to the "CBOR Web Token Claims" registry following the procedure specified in {{RFC8392}}.

* Claim Name: "edhoc_params"
* Claim Description: Parameters of the EDHOC application profile to use
* JWT Claim Name: "edhoc_params"
* Claim Key: TBD
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

## JWT Confirmation Methods Registry ## {#iana-jwt-confirmation-methods}

IANA is asked to add the following entries to the "JWT Confirmation Methods" registry following the procedure specified in {{RFC7800}}.

* Confirmation Method Value: "x5bag"
* Confirmation Method Description: An unordered bag of X.509 certificates
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "x5chain"
* Confirmation Method Description: An ordered chain of X.509 certificates
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "x5t"
* Confirmation Method Description: Hash of an X.509 certificate
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "x5u"
* Confirmation Method Description: URI pointing to an X.509 certificate
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "c5b"
* Confirmation Method Description: An unordered bag of C509 certificates
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "c5c"
* Confirmation Method Description: An ordered chain of C509 certificates
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "c5t"
* Confirmation Method Description: Hash of an C509 certificate
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "c5u"
* Confirmation Method Description: URI pointing to a COSE_C509 containing an ordere chain of certificates
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "kcwt"
* Confirmation Method Description: A CBOR Web Token (CWT) containing a COSE_Key in a 'cnf' claim
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Value: "kccs"
* Confirmation Method Description: A CWT Claims Set (CCS) containing a COSE_Key in a 'cnf' claim
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

## CWT Confirmation Methods Registry ## {#iana-cwt-confirmation-methods}

IANA is asked to add the following entries to the "CWT Confirmation Methods" registry following the procedure specified in {{RFC8747}}.

* Confirmation Method Name: x5bag
* Confirmation Method Description: An unordered bag of X.509 certificates
* JWT Confirmation Method Name: "x5bag"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_X509
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: x5chain
* Confirmation Method Description: An ordered chain of X.509 certificates
* JWT Confirmation Method Name: "x5chain"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_X509
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: x5t
* Confirmation Method Description: Hash of an X.509 certificate
* JWT Confirmation Method Name: "x5t"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_CertHash
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: x5u
* Confirmation Method Description: URI pointing to an X.509 certificate
* JWT Confirmation Method Name: "x5u"
* Confirmation Key: TBD
* Confirmation Value Type(s): uri
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: c5b
* Confirmation Method Description: An unordered bag of C509 certificates
* JWT Confirmation Method Name: "c5b"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_C509
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: c5c
* Confirmation Method Description: An ordered chain of C509 certificates
* JWT Confirmation Method Name: "c5c"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_C509
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: c5t
* Confirmation Method Description: Hash of an C509 certificate
* JWT Confirmation Method Name: "c5t"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_CertHash
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: c5u
* Confirmation Method Description: URI pointing to a COSE_C509 containing an ordere chain of certificates
* JWT Confirmation Method Name: "c5u"
* Confirmation Key: TBD
* Confirmation Value Type(s): uri
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: kcwt
* Confirmation Method Description: A CBOR Web Token (CWT) containing a COSE_Key in a 'cnf' claim
* JWT Confirmation Method Name: "kcwt"
* Confirmation Key: TBD
* Confirmation Value Type(s): COSE_Messages
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

&nbsp;

* Confirmation Method Name: kccs
* Confirmation Method Description: A CWT Claims Set (CCS) containing a COSE_Key in a 'cnf' claim
* JWT Confirmation Method Name: "kccs"
* Confirmation Key: TBD
* Confirmation Value Type(s): map / #6(map)
* Change Controller: IESG
* Specification Document(s): {{&SELF}}

## EDHOC Application Profile Parameters Registry # {#iana-edhoc-parameters}

It is requested that IANA create a new registry entitled "EDHOC Application Profile Parameters" registry. The registry is to be created as Expert Review Required {{RFC8126}}. Guidelines for the experts are provided in {{iana-expert-review}}. It should be noted that in addition to the expert review, some portions of the registry require a specification, potentially on standards track, be supplied as well.

The columns of the registry are:

* Name: A descriptive name that enables easier reference to this item. Because a core goal of this document is for the resulting representations to be compact, it is RECOMMENDED that the name be short.

   This name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts determine that there is a compelling reason to allow an exception. The name is not used in the CBOR encoding.

* CBOR Value: The value to be used as CBOR abbreviation of the item.

   The value MUST be unique. The value can be a positive integer, a negative integer or a string.  Integer values between -256 and 255 and strings of length 1 are designated as Standards Track Document required. Integer values from -65536 to -257 and from 256 to 65535 and strings of maximum length 2 are designated as Specification Required. Integer values greater than 65535 and strings of length greater than 2 are designated as Expert Review. Integer values less than -65536 are marked as Private Use.

* CBOR Type: The CBOR type of the item, or a pointer to the registry that defines its type, when that depends on another item.

* Registry: The registry that values of the item may come from, if one exists.

* Description: A brief description of this item.

* Specification: A pointer to the public specification for the item, if one exists.

This registry will be initially populated by the values in {{key-edhoc-params}}. The specification column for all of these entries will be this document and {{I-D.ietf-core-oscore-edhoc}}.

## Expert Review Instructions # {#iana-expert-review}

\[ TODO \]

--- back

# Examples # {#examples}

This appendix provides examples where this profile of ACE is used. In particular:

* {{example-without-optimization}} does not make use of use of any optimization.

* {{example-with-optimization}} makes use of the optimizations defined in this specification, hence reducing the roundtrips of the interactions between the Client and RS.

* {{example-without-optimization-as-posting}} does not make use of any optimization, but consider an alternative workflow where the AS uploads the access token to the RS.

All these examples build on the following assumptions, as relying on expected early procedures performed at the AS. These include the registration of RSs by the respective Resource Owners as well as the registrations of Clients authorized to request access token for those RSs.

* The AS knows the authentication credential AUTH_CRED_C of the Client C.

* The Client knows the authentication credential AUTH_CRED_AS of the AS.

* The AS knows the authentication credential AUTH_CRED_RS of RS.

* The RS knows the authentication credential AUTH_CRED_AS of the AS.

   This is relevant in case the AS and RS actually require a secure association (e.g., for the RS to perform token introspection at the AS, or for the AS to upload an access token to the RS on behalf of the Client).

As a result of the assumptions above, it is possible to limit the transport of AUTH_CRED_C and AUTH_CRED_RS by value only to the following two cases, and only when the Client requests an access token for the RS in question for the first time when considering the pair (AUTH_CRED_C, AUTH_CRED_RS).

* In the Token Response from the AS to the Client, where AUTH_CRED_RS is specified by the 'rs_cnf' parameter.

* In the access token, where AUTH_CRED_C is specified by the 'cnf' claim.

   Note that, even under the circumstances mentioned above, AUTH_CRED_C might rather be indicated by reference. This is possible if the RS can effectively use such a reference from the access token to retrieve AUTH_CRED_C (e.g., from a trusted repository of authentication credentials reachable through a non-constrained link), and if the AS is in turn aware of that.

In any other case, it is otherwise possible to indicate both AUTH_CRED_C and AUTH_CRED_RS by reference, when performing the ACE access control workflow as well as later on when the Client and RS run EDHOC.

## Workflow without Optimizations # {#example-without-optimization}

The example below considers the simplest (though least efficient) interaction between the Client and RS. That is: first the Client uploads the access token to the RS; then the Client and RS run EDHOC; and, finally, the Client accesses the protected resource at the RS.

~~~~~~~~~~~~~~~~~~~~~~~
    C                                 AS                             RS
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
M03 |--------------------------------->|                              |
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M04 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     AUTH_CRED_C by reference     |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M05 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  the 'cnf' claim in the          |                              |
    |     access token specifies       |                              |
    |     AUTH_CRED_C by value         |                              |
    |                                  |                              |

 // Possibly after chain verification, the Client adds AUTH_CRED_RS
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M06 |---------------------------------------------------------------->|
    |                                  |                              |

 // Possibly after chain verification, the RS adds AUTH_CRED_C
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |   2.01 (Created)                 |                              |
    |   (unprotected message)          |                              |
M07 |<----------------------------------------------------------------|
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M08 |---------------------------------------------------------------->|
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M09 |<----------------------------------------------------------------|
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M10 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Access to protected resource    |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M11 |---------------------------------------------------------------->|
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M12 |<----------------------------------------------------------------|
    |                                  |                              |

 // Later on, the access token expires ...
 //  - The Client and RS delete their OSCORE Security Context and
 //    terminate the EDHOC session used to derive it (unless the same
 //    session is also used for other reasons).
 //  - The RS retains AUTH_CRED_C as still valid,
 //    and the AS knows about it.
 //  - The Client retains AUTH_CRED_RS as still valid,
 //    and the AS knows about it.

    |                                  |                              |
    |                                  |                              |

 // Time passes ...

    |                                  |                              |
    |                                  |                              |

 // The Client asks for a new access token; now all the
 // authentication credentials can be indicated by reference

 // The price to pay is on the AS, about remembering that at least
 // one access token has been issued for the pair (Client, RS)
 // and considering the pair (AUTH_CRED_C, AUTH_CRED_RS)

    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M13 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M14 |<---------------------------------|                              |
    |  'rs_cnf' identifies             |                              |
    |     AUTH_CRED_RS                 |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  the 'cnf' claim in the          |                              |
    |  access token identifies         |                              |
    |  AUTH_CRED_C by reference        |                              |
    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M15 |---------------------------------------------------------------->|
    |                                  |                              |
    |   2.01 (Created)                 |                              |
    |  (unprotected message)           |                              |
M16 |<----------------------------------------------------------------|
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M17 |---------------------------------------------------------------->|
    |                                  |                              |
    |  EDHOC message_2                 |                              |
    |  (no access control is enforced) |                              |
M18 |<----------------------------------------------------------------|
    |  ID_CRED_R specifies             |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M19 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M20 |---------------------------------------------------------------->|
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M21 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~~~~~~~~~~~~~

## Workflow with Optimizations # {#example-with-optimization}

The example below builds on the example in {{example-without-optimization}}, while additionally relying on the two following optimizations.

* The access token is not separately uploaded to the /authz-info endpoint at the RS, but rather included in the EAD_1 parameter of EDHOC message_1 sent by the Client to the RS.

* The Client uses the EDHOC+OSCORE request defined in {{I-D.ietf-core-oscore-edhoc}} is used, when running EDHOC both with the AS and with the RS.

These two optimizations used together result in the most efficient interaction between the Client and RS, as consisting of only two roundtrips to upload the access token, run EDHOC and access the protected resource at the RS.

Also, a further optimization is used upon uploading a second access token to the RS, following the expiration of the first one. That is, after posting the second access token, the Client and RS do not run EDHOC again, but rather EDHOC-KeyUpdate() and EDHOC-Exporter() building on the same EDHOC session established before.

~~~~~~~~~~~~~~~~~~~~~~~
    C                                 AS                             RS
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC+OSCORE request to /token  |                              |
M03 |--------------------------------->|                              |
    |  EDHOC message_3                 |                              |
    |   ID_CRED_I identifies           |                              |
    |   CRED_I = AUTH_CRED_C           |                              |
    |   by reference                   |                              |
    |  --- --- ---                     |                              |
    |  (OSCORE-protected part)         |                              |
    |  Token request                   |                              |
    |    'req_cnf' identifies          |                              |
    |    AUTH_CRED_C by reference      |                              |
    |  )                               |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M04 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  the 'cnf' claim in the          |                              |
    |     access token specifies       |                              |
    |     AUTH_CRED_C by value         |                              |
    |                                  |                              |

 // Possibly after chain verification, the Client adds AUTH_CRED_RS
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M05 |---------------------------------------------------------------->|
    |  Access token specified in EAD_1 |                              |
    |                                  |                              |

 // Possibly after chain verification, the RS adds AUTH_CRED_C
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |  EDHOC message_2                 |                              |
M06 |<----------------------------------------------------------------|
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC+OSCORE request to /r      |                              |
M07 |---------------------------------------------------------------->|
    |  EDHOC message_3                 |                              |
    |   ID_CRED_I identifies           |                              |
    |   CRED_I = AUTH_CRED_C           |                              |
    |   by reference                   |                              |
    |  --- --- ---                     |                              |
    |  (OSCORE-protected part)         |                              |
    |  Application request to /r       |                              |
    |                                  |                              |

 // After the EDHOC processing is completed, access control
 // is enforced on the rebuilt OSCORE-protected request,
 // like if it had been sent stand-alone

    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M08 |<----------------------------------------------------------------|
    |                                  |                              |

 // Later on, the access token expires ...
 //  - The Client and RS delete their OSCORE Security Context and
 //    terminate the EDHOC session used to derive it (unless the same
 //    session is also used for other reasons).
 //  - The RS retains AUTH_CRED_C as still valid,
 //    and the AS knows about it.
 //  - The Client retains AUTH_CRED_RS as still valid,
 //    and the AS knows about it.

    |                                  |                              |
    |                                  |                              |

 // Time passes ...

    |                                  |                              |
    |                                  |                              |

 // The Client asks for a new access token; now all the
 // authentication credentials can be indicated by reference

 // The price to pay is on the AS, about remembering that at least
 // one access token has been issued for the pair (Client, RS)
 // and considering the pair (AUTH_CRED_C, AUTH_CRED_RS)

    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M09 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M10 |<---------------------------------|                              |
    |  'rs_cnf' identifies             |                              |
    |     AUTH_CRED_RS                 |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  the 'cnf' claim in the          |                              |
    |  access token identifies         |                              |
    |  AUTH_CRED_C by reference        |                              |
    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M11 |---------------------------------------------------------------->|
    |   Payload {                      |                              |
    |     access token,                |                              |
    |     N1 // nonce                  |                              |
    |   }                              |                              |
    |                                  |                              |
    |   2.01 (Created)                 |                              |
    |  (unprotected message)           |                              |
M12 |<----------------------------------------------------------------|
    |   Payload {                      |                              |
    |     N2 // nonce                  |                              |
    |   }                              |                              |
    |                                  |                              |

 // The Client and RS first run EDHOC-KeyUpdate(N1 | N2), and
 // then EDHOC-Exporter() to derive a new OSCORE Master Secret and
 // OSCORE Master Salt, from which a new OSCORE Security Context is
 // derived. The Sender/Recipiend IDs are the same C_I and C_R from
 // the previous EDHOC execution

    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M13 |---------------------------------------------------------------->|
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M14 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~~~~~~~~~~~~~

## Workflow without Optimizations (AS token posting) # {#example-without-optimization-as-posting}

The example below builds on the example in {{example-without-optimization}}, but assumes that the AS is uploading the access token to the RS on behalf of C.

In order to save roundtrips between the Client and RS, further, more efficient interactions can be seamlessly considered, e.g., as per the example in {{example-with-optimization}}.

~~~~~~~~~~~~~~~~~~~~~~~
    C                                 AS                             RS
    |                                  | Establish secure association |
    |                                  | (e.g., OSCORE using EDHOC)   |
    |                                  |<---------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
M03 |--------------------------------->|                              |
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M04 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     AUTH_CRED_C by reference     |                              |
    |                                  |                              |
    |                                  |                              |
    |                                  |  Token upload to /authz-info |
    |                                  |  (OSCORE-protected message)  |
M05 |                                  |----------------------------->|
    |                                  |  the 'cnf' claim in the      |
    |                                  |     access token specifies   |
    |                                  |     AUTH_CRED_C by value     |
    |                                  |                              |

 // Possibly after chain verification, the RS adds AUTH_CRED_C
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |                                  |  2.01 (Created)              |
    |                                  |  (OSCORE-protected message)  |
M06 |                                  |<-----------------------------|
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M07 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |


 // Possibly after chain verification, the Client adds AUTH_CRED_RS
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M08 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M09 |<----------------------------------------------------------------|
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M10 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Access to protected resource    |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M11 |---------------------------------------------------------------->|
    |                                  |                              |

 // After the EDHOC processing is completed, access control
 // is enforced on the rebuilt OSCORE-protected request,
 // like if it had been sent stand-alone

    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M12 |<----------------------------------------------------------------|
    |                                  |                              |
    |                                  |                              |

 // Later on, the access token expires ...
 //  - The Client and RS delete their OSCORE Security Context and
 //    terminate the EDHOC session used to derive it (unless the same
 //    session is also used for other reasons).
 //  - The RS retains AUTH_CRED_C as still valid,
 //    and the AS knows about it.
 //  - The Client retains AUTH_CRED_RS as still valid,
 //    and the AS knows about it.

    |                                  |                              |
    |                                  |                              |

 // Time passes ...

    |                                  |                              |
    |                                  |                              |

 // The Client asks for a new access token; now all the
 // authentication credentials can be indicated by reference

 // The price to pay is on the AS, about remembering that at least
 // one access token has been issued for the pair (Client, RS)
 // and considering the pair (AUTH_CRED_C, AUTH_CRED_RS)

    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M13 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |  Token upload to /authz-info |
    |                                  |  (OSCORE-protected message)  |
M14 |                                  |----------------------------->|
    |                                  |  the 'cnf' claim in the      |
    |                                  |     access token specifies   |
    |                                  |     AUTH_CRED_C by value     |
    |                                  |                              |
    |                                  |  2.01 (Created)              |
    |                                  |  (OSCORE-protected message)  |
M15 |                                  |<-----------------------------|
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M16 |<---------------------------------|                              |
    |  'rs_cnf' identifies             |                              |
    |     AUTH_CRED_RS                 |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M17 |---------------------------------------------------------------->|
    |                                  |                              |
    |  EDHOC message_2                 |                              |
    |  (no access control is enforced) |                              |
M18 |<----------------------------------------------------------------|
    |  ID_CRED_R specifies             |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M19 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M20 |---------------------------------------------------------------->|
    |                                  |                              |

 // After the EDHOC processing is completed, access control
 // is enforced on the rebuilt OSCORE-protected request,
 // like if it had been sent stand-alone

    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M21 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~~~~~~~~~~~~~

# Acknowledgments # {#acknowldegment}
{: numbered="no"}

Work on this document has in part been supported by the H2020 project SIFIS-Home (grant agreement 952652).
