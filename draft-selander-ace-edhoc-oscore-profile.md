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
  RFC8610:
  RFC8613:
  RFC8747:
  RFC8949:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-ace-oauth-params:
  I-D.ietf-lake-edhoc:
  I-D.ietf-core-oscore-edhoc:
  I-D.ietf-cose-x509:
  I-D.ietf-cose-cbor-encoded-cert:

informative:
  RFC4949:
  RFC5869:
  RFC7231:
  RFC7662:
  RFC7748:
  RFC8032:
  RFC8446:
  RFC9147:
  I-D.ietf-ace-oscore-profile:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document specifies a profile for the Authentication and Authorization for Constrained Environments (ACE) framework.
It utilizes Ephemeral Diffie-Hellman Over COSE (EDHOC) for achieving mutual authentication between an OAuth 2.0 Client and Resource Server, and it binds an authentication credential of the Client to an OAuth 2.0 access token.
EDHOC also establishes an Object Security for Constrained RESTful Environments (OSCORE) Security Context, which is used to secure communications when accessing protected resources according to the authorization information indicated in the access token.
A resource-constrained server can use this profile to delegate management of authorization information to a trusted host with less severe limitations regarding processing power and memory.

--- middle


# Introduction

This document defines the "coap_edhoc_oscore" profile of the ACE framework {{I-D.ietf-ace-oauth-authz}}. This profile addresses a "zero-touch" constrained setting where trusted operations can be performed with low overhead without endpoint specific configurations.

Like in the "coap_oscore" profile {{I-D.ietf-ace-oscore-profile}}, also in this profile a client (C) and a resource server (RS) use the Constrained Application Protocol (CoAP) {{RFC7252}} to communicate, and Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} to protect their communications. Besides, the processing of requests for specific protected resources is identical to what is defined in the "coap_oscore" profile.

When using this profile, C accesses protected resources hosted at the RS with the use of an access token issued by a trusted authorization server (AS) and bound to an authentication credential of C. This differs from the "coap_oscore" profile, where the access token is bound to a symmetric key used to derive OSCORE keying material. As recommended in {{I-D.ietf-ace-oauth-authz}}, this document uses CBOR Web Tokens (CWTs) {{RFC8392}} as access tokens.

The authentication and authorization workflow requires C and the RS to have access to each other's authentication credentials. In particular, C obtains both an access token and an authentication credential of the RS from the AS, while the RS can obtain the access token for C (and the authentication credential of C included therin) through different possible options. If the RS successfully verifies the access token, then C and the RS run the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol {{I-D.ietf-lake-edhoc}}, with each peer using its own and the other peer's authentication credential.

Once completed the EDHOC execution, C and the RS are mutually authenticated and establish an OSCORE Security Context to protect following communications, while the RS achieves proof of possession of the private key of C. Instead, C achieves proof of possession of the private key of the RS either once completed the EDHOC execution (if an optional, fourth EDHOC message is sent by the RS) or after the first message exchange using OSCORE.

Authentication credentials can be a raw public key, e.g., encoded as a CWT Claims Set (CCS, {{RFC8392}}); or a public key certificate, e.g., encoded as an X.509 certificate or as a CBOR encoded X.509 certificate (C509, {{I-D.ietf-cose-cbor-encoded-cert}}); or a different type of data structure containing (or uniquely referring to) the public key of the peer in question.

The ACE protocol establishes what those authentication credentials are, and may transport the actual authentication credentials by value or rather uniquely refer to them. If an actual authentication credential is pre-provisioned or can be obtained over less constrained links, then it suffices that ACE provides a unique reference such as a certificate hash (e.g., by using the COSE header parameter "x5t", see {{I-D.ietf-cose-x509}}). This is in the same spirit as EDHOC, where the authentication credentials may be transported or referenced in the ID_CRED_x message fields (see Section 3.5.3 of {{I-D.ietf-lake-edhoc}}).

Generally, the AS and RS are likely to have trusted access to each other's authentication credentials, since the AS acts on behalf of the RS as per the trust model of ACE. Also, the AS needs to have some information about C, including the respective authentication credential, in order to identify C when it requests an access token and to determine what access rights it can be granted. However, the authentication credential of C may potentially be conveyed (or uniquely referred to) within the request sent to the AS.

## Terminology

{::boilerplate bcp14}

Certain security-related terms such as "authentication", "authorization", "confidentiality", "(data) integrity", "Message Authentication Code (MAC)", "Hash-based Message Authentication Code (HMAC)", and "verify" are taken from {{RFC4949}}.

RESTful terminology follows HTTP {{RFC7231}}.

Readers are expected to be familiar with the terms and concepts defined in CoAP {{RFC7252}}, OSCORE {{RFC8613}} and EDHOC {{I-D.ietf-lake-edhoc}}.

Readers are also expected to be familiar with the terms and concepts of the ACE framework described in {{I-D.ietf-ace-oauth-authz}} and in {{I-D.ietf-ace-oauth-params}}.

Terminology for entities in the architecture is defined in OAuth 2.0 {{RFC6749}}, such as client (C), resource server (RS), and authorization server (AS).  It is assumed in this document that a given resource on a specific RS is associated to a unique AS.

Note that the term "endpoint" is used here, as in {{I-D.ietf-ace-oauth-authz}}, following its OAuth definition, which is to denote resources such as token and introspect at the AS and authz-info at the RS. The CoAP {{RFC7252}} definition, which is "An entity participating in the CoAP protocol" is not used in this document.

The authorization information (authz-info) resource refers to the authorization information endpoint as specified in {{I-D.ietf-ace-oauth-authz}}. The term "claim" is used in this document with the same semantics as in {{I-D.ietf-ace-oauth-authz}}, i.e., it denotes information carried in the access token or returned from introspection.

Concise Binary Object Representation (CBOR) {{RFC8949}} and Concise Data Definition Language (CDDL) {{RFC8610}} are used in this document. CDDL predefined type names, especially bstr for CBOR byte strings and tstr for CBOR text strings, are used extensively in this document.

Examples throughout this document are expressed in CBOR diagnostic notation without the tag and value abbreviations.

# Protocol Overview {#overview}

This section gives an overview of how to use the ACE framework {{I-D.ietf-ace-oauth-authz}} together with the authenticated key establishment protocol EDHOC {{I-D.ietf-lake-edhoc}}. By doing so, a client (C) and a resource server (RS) generate an OSCORE Security Context {{RFC8613}} associated with authorization information, and use that Security Context to protect their communications. The parameters needed by C to negotiate the use of this profile with the authorization server (AS), as well as the OSCORE setup process, are described in detail in the following sections.

The RS maintains a collection of authentication credentials. These are related to OSCORE Security Contexts associated with authorization information for all the clients that the RS is communicating with. The authorization information is maintained as policy that is used as input to the processing of requests from those clients.

This profile requires C to retrieve an access token from the AS for the resources it wants to access on an RS, by sending an access token request to the token endpoint, as specified in Section 5.8 of {{I-D.ietf-ace-oauth-authz}}. The access token request and response MUST be confidentiality protected and ensure authenticity. The use of EDHOC and OSCORE between C and the AS is RECOMMENDED in this profile, in order to reduce the number of libraries that C has to support. However, other protocols fulfilling the security requirements defined in Section 5 of {{I-D.ietf-ace-oauth-authz}} MAY alternatively be used, such as TLS {{RFC8446}} or DTLS {{RFC9147}}.

Once C has retrieved the access token, C uploads it to the RS. To this end, there are two different options, as further detailed in this document.

* C posts the access token to the authz-info endpoint by using the mechanisms specified in Section 5.8 of {{I-D.ietf-ace-oauth-authz}}. If the access token is valid, the RS responds to the request with a 2.01 (Created) response, after which C initiates the EDHOC protocol by sending EDHOC message_1 to the RS. When using this profile, the communication with the authz-info endpoint is not protected, except for the update of access rights.

* C initiates the EDHOC protocol by sending EDHOC message_1 to the RS, specifying the access token as External Authorization Data (EAD) in the field EAD_1 of EDHOC message_1 (see Section 3.8 {{I-D.ietf-lake-edhoc}}). If the access token is valid and the processing of EDHOC message_1 is successful, the RS responds with EDHOC message_2, thus continuing the EDHOC protocol. This alternative cannot be used for the update of access rights.

When running the EDHOC protocol, C uses the authentication credential of RS specified by the AS together with the access token, while the RS uses the authentication credential of C bound to and specified within the access token. If C and RS complete the EDHOC execution successfully, they are mutually authenticated and they derive an OSCORE Security Context as per {{Section A.1 of I-D.ietf-lake-edhoc}}. Also, the RS associates the authentication credential of C with the derived OSCORE Security Context and with the access rights of C specified in the access token.

From then on, C effectively gains authorized and secure access to protected resources on the RS, as long as the access token is valid. Until then, C can communicate with the RS by sending a request protected with the OSCORE Security Context established above. The OSCORE Security Context is discarded when a token (whether the same or a different one) is used to successfully derive a new OSCORE Security Context for C, either by re-running the EDHOC protocol or by exchanging nonces and using the EDHOC-KeyUpdate function (see {{edhoc-key-update}}).

After the whole message exchange has taken place, C can contact the AS to request an update of its access rights, by sending a similar request to the token endpoint that also includes an identifier, which allows the AS to find the correct data it has previously shared with C. This specific identifier, encoded as a byte string, is uniquely assigned by the AS to a "dynasty" of access tokens. In particular, all access tokens in a dynasty are issued to the same C for the same RS, with the AS specifying to C (to the RS) the same authentication credential of the RS (of C). Upon a successful update of access rights, the new issued access token becomes the latest one of its dynasty. When the current, latest issued access token of a dynasty becomes invalid (e.g., when it expires), that dynasty ends.

An overview of the profile flow for the "coap_edhoc_oscore" profile is given in {{protocol-overview}}. The names of messages coincide with those of {{I-D.ietf-ace-oauth-authz}} when applicable.

~~~~~~~~~~~~~~~~~~~~~~~

   C                            RS                       AS
   |                            |                         |
   | <==== Mutual authentication and secure channel ====> |
   |                            |                         |
   | ------- POST /token  ------------------------------> |
   |                            |                         |
   | <-------------------------------- Access Token ----- |
   |                               + Access Information   |
   |                            |                         |
   | ---- POST /authz-info ---> |                         |
   |       (access_token)       |                         |
   |                            |                         |
   | <----- 2.01 Created ------ |                         |
   |                            |                         |
   | <========= EDHOC ========> |                         |
   |  Mutual authentication     |                         |
   |  and derivation of an      |                         |
   |  OSCORE Security Context   |                         |
   |                            |                         |
   |                /Proof-of-possession and              |
   |                Security Context storage/             |
   |                            |                         |
   | ---- OSCORE Request -----> |                         |
   |                            |                         |
   | <--- OSCORE Response ----- |                         |
   |                            |                         |
/Proof-of-possession            |                         |
and Security Context            |                         |
storage (latest)/               |                         |
   |                            |                         |
   | ---- OSCORE Request -----> |                         |
   |                            |                         |
   | <--- OSCORE Response ----- |                         |
   |                            |                         |
   |           ...              |                         |

~~~~~~~~~~~~~~~~~~~~~~~
{: #protocol-overview title="Protocol Overview"}


# Client-AS Communication # {#c-as-comm}

TBD

## C-to-AS: POST to token endpoint # {#c-as}

TBD

## AS-to-C: Access Token # {#as-c}

TBD

### The EDHOC_Parameters Object # {#edhoc-params-object}

TBD

# Client-RS Communication # {#c-rs-comm}

TBD

## C-to-RS: POST to authz-info endpoint # {#c-rs}

TBD

## RS-to-C: 2.01 (Created) # {#rs-c}

TBD

## EDHOC Execution and OSCORE Setup # {#edhoc-exec}

TBD

## Access Rights Verification # {#access-rights-verif}

TBD

# Secure Communication with the AS # {#secure-comm-as}

TBD

# Discarding the Security Context # {#discard-context}

TBD

# Use of EDHOC-KeyUpdate # {#edhoc-key-update}

TBD

# EDHOC Application Profile Parameters # {#key-edhoc-params}

This specification defines a number of EDHOC application profile parameters that can be transported in the 'edhoc_params' parameter of a Token Response to the Client, or in the 'edhoc_params' claim of an access token.

In the former case, when the response payload is encoded as a CBOR map, the response MUST use the Content-Format "application/ace+cbor" defined in {{I-D.ietf-ace-oauth-authz}}.

The table below summarizes them, and specifies the CBOR value to use as abbreviation instead of the full descriptive name.

~~~~~~~~~~~
+--------------+------+--------------+----------+---------------------+
| Name         | CBOR | CBOR value   | Registry | Description         |
|              | Type |              |          |                     |
+--------------+------+--------------+----------+---------------------+
| id           | TBD  | bstr         |          | EDHOC session       |
|              |      |              |          | identifier          |
+--------------+------+--------------+----------+---------------------+
| methods      | TBD  | int / array  | EDHOC    | EDHOC methods       |
|              |      |              | Method   | possible to use     |
|              |      |              | Type     | between the Client  |
|              |      |              | Registry | and RS              |
+--------------+------+--------------+----------+---------------------+
| cipher_suite | TBD  | int          | EDHOC    | The EDHOC cipher    |
|              |      |              | Cipher   | suite to use as     |
|              |      |              | Suites   | selected cipher     |
|              |      |              | Registry | suite               |
+--------------+------+--------------+----------+---------------------+
| osc_ms_len   | TBD  | uint         |          | Length in bytes of  |
|              |      |              |          | the OSCORE Master   |
|              |      |              |          | Secret to derive    |
|              |      |              |          | with EDHOC-Exporter |
+--------------+------+--------------+----------+---------------------+
| osc_salt_len | TBD  | uint         |          | Length in bytes of  |
|              |      |              |          | the OSCORE Master   |
|              |      |              |          | Salt to derive      |
|              |      |              |          | with EDHOC-Exporter |
+--------------+------+--------------+----------+---------------------+
| key_update   | TBD  | simple value |          | Indication on the   |
|              |      | "true" /     |          | RS support for      |
|              |      | simple value |          | EDHOC-KeyUpdate     |
|              |      | "false"      |          |                     |
+--------------+------+--------------+----------+---------------------+
| message_4    | TBD  | simple value |          | Indication on the   |
|              |      | "true" /     |          | RS support for      |
|              |      | simple value |          | EDHOC message_4     |
+--------------+------+--------------+----------+---------------------+
| comb_req     | TBD  | simple value |          | Indication on the   |
|              |      | "true" /     |          | RS support for the  |
|              |      | simple value |          | EDHOC+OSCORE        |
|              |      | "false"      |          | combined request    |
+--------------+------+--------------+----------+---------------------+
| uri_path     | TBD  | tstr         |          | URI-path of the     |
|              |      |              |          | EDHOC resource at   |
|              |      |              |          | the RS              |
+--------------+------+--------------+----------+---------------------+
~~~~~~~~~~~
{: #fig-cbor-key-edhoc-params title="CBOR abbreviations for the EDHOC application profile parameters" artwork-align="center"}

# Security Considerations

TBD

# Privacy Considerations

TBD

# IANA Considerations

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with
the RFC number of this specification and delete this paragraph.

## ACE OAuth Profile Registry ## {#iana-ace-oauth-profile}

IANA is asked to add the following entry to the "ACE OAuth Profile"
Registry following the procedure specified in {{I-D.ietf-ace-oauth-authz}}.

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

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" following the procedure specified in {{I-D.ietf-ace-oauth-authz}}.

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

It is requested that IANA create a new registry entitled "EDHOC Application Profile Parameters" registry. The registry is to be created with registration policy Expert Review {{RFC8126}}. Guidelines for the experts are provided in {{iana-expert-review}}. It should be noted that in addition to the expert review, some portions of the registry require a specification, potentially on Standards Track, be supplied as well.

The columns of the registry are:

* Name: A descriptive name that enables easier reference to this item. Because a core goal of this document is for the resulting representations to be compact, it is RECOMMENDED that the name be short.

   This name is case sensitive. Names may not match other registered names in a case-insensitive manner unless the Designated Experts determine that there is a compelling reason to allow an exception. The name is not used in the CBOR encoding.

* CBOR Value: The value to be used as CBOR abbreviation of the item.

   The value MUST be unique. The value can be a positive integer, a negative integer or a string. Integer values between -256 and 255 and strings of length 1 are to be registered by Standards Track documents (Standards Action). Integer values from -65536 to -257 and from 256 to 65535 and strings of maximum length 2 are to be registered by public specifications (Specification Required). Integer values greater than 65535 and strings of length greater than 2 are subject to the Expert Review policy. Integer values less than -65536 are marked as private use.

* CBOR Type: The CBOR type of the item, or a pointer to the registry that defines its type, when that depends on another item.

* Registry: The registry that values of the item may come from, if one exists.

* Description: A brief description of this item.

* Specification: A pointer to the public specification for the item, if one exists.

This registry will be initially populated by the values in {{key-edhoc-params}}. The "Specification" column for all of these entries will be this document and {{I-D.ietf-core-oscore-edhoc}}.

## Expert Review Instructions # {#iana-expert-review}

The IANA registry established in this document is defined to use the registration policy Expert Review. This section gives some general guidelines for what the experts should be looking for, but they are being designated as experts for a reason so they should be given substantial latitude.

Expert reviewers should take into consideration the following points:

* Point squatting should be discouraged. Reviewers are encouraged to get sufficient information for registration requests to ensure that the usage is not going to duplicate one that is already registered and that the point is likely to be used in deployments. The zones tagged as private use are intended for testing purposes and closed environments; code points in other ranges should not be assigned for testing.

* Specifications are required for the Standards Action range of point assignment. Specifications should exist for Specification Required ranges, but early assignment before a specification is available is considered to be permissible. Specifications are needed for the first-come, first-serve range if they are expected to be used outside of closed environments in an interoperable way. When specifications are not provided, the description provided needs to have sufficient information to identify what the point is being used for.

* Experts should take into account the expected usage of fields when approving point assignment. The fact that there is a range for Standards Track documents does not mean that a Standards Track document cannot have points assigned outside of that range. The length of the encoded value should be weighed against how many code points of that length are left, the size of device it will be used on, and the number of code points left that encode to that size.

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
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
M03 |--------------------------------->|                              |
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token request to /token         |                              |
    |  (OSCORE-protected message)      |                              |
M04 |--------------------------------->|                              |
    |  'req_cnf' identifies            |                              |
    |     AUTH_CRED_C by reference     |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M05 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'01',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |     * the 'cnf' claim specifies  |                              |
    |       AUTH_CRED_C by value       |                              |
    |     * the 'edhoc_params' claim   |                              |
    |       specifies the same as      |                              |
    |       'edhoc_params' above       |                              |
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
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M14 |<---------------------------------|                              |
    |  'rs_cnf' identifies             |                              |
    |     AUTH_CRED_RS by reference    |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'05',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |     * the 'cnf' claim specifies  |                              |
    |       AUTH_CRED_C by reference   |                              |
    |     * the 'edhoc_params' claim   |                              |
    |       specifies the same as      |                              |
    |       'edhoc_params' above       |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M15 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  2.01 (Created)                 |                              |
    |  (unprotected message)           |                              |
M16 |<----------------------------------------------------------------|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M17 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
    |  (no access control is enforced) |                              |
M18 |<----------------------------------------------------------------|
    |  ID_CRED_R specifies             |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M19 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M20 |---------------------------------------------------------------->|
    |                                  |                              |
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
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC+OSCORE request to /token  |                              |
M03 |--------------------------------->|                              |
    |  * EDHOC message_3               |                              |
    |      ID_CRED_I identifies        |                              |
    |         CRED_I = AUTH_CRED_C     |                              |
    |         by reference             |                              |
    |  --- --- ---                     |                              |
    |  * OSCORE-protected part         |                              |
    |      Token request               |                              |
    |         'req_cnf' identifies     |                              |
    |         AUTH_CRED_C by reference |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M04 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'01',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |     * the 'cnf' claim specifies  |                              |
    |       AUTH_CRED_C by value       |                              |
    |     * the 'edhoc_params' claim   |                              |
    |       specifies the same as      |                              |
    |       'edhoc_params' above       |                              |
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
    |  * EDHOC message_3               |                              |
    |      ID_CRED_I identifies        |                              |
    |         CRED_I = AUTH_CRED_C     |                              |
    |         by reference             |                              |
    |  --- --- ---                     |                              |
    |  * OSCORE-protected part         |                              |
    |      Application request to /r   |                              |
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
    |     AUTH_CRED_RS by reference    |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'05',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
    |                                  |                              |
    |  In the access token:            |                              |
    |     * the 'cnf' claim specifies  |                              |
    |       AUTH_CRED_C by reference   |                              |
    |     * the 'edhoc_params' claim   |                              |
    |       specifies the same as      |                              |
    |       'edhoc_params' above       |                              |
    |                                  |                              |
    |                                  |                              |
    |  Token upload to /authz-info     |                              |
    |  (unprotected message)           |                              |
M11 |---------------------------------------------------------------->|
    |   Payload {                      |                              |
    |     access_token: access token   |                              |
    |     nonce_1: N1  // nonce        |                              |
    |   }                              |                              |
    |                                  |                              |
    |                                  |                              |
    |  2.01 (Created)                  |                              |
    |  (unprotected message)           |                              |
M12 |<----------------------------------------------------------------|
    |   Payload {                      |                              |
    |     nonce_2: N2  // nonce        |                              |
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
    |                                  |                              |
    |                                  | Establish secure association |
    |                                  | (e.g., OSCORE using EDHOC)   |
    |                                  |<---------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
M01 |--------------------------------->|                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
M02 |<---------------------------------|                              |
    |  ID_CRED_R identifies            |                              |
    |     CRED_R = AUTH_CRED_AS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
M03 |--------------------------------->|                              |
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
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
    |                                  |  In the access token:        |
    |                                  |     * the 'cnf' claim        |
    |                                  |       specifies AUTH_CRED_C  |
    |                                  |       by value               |
    |                                  |     * the 'edhoc_params'     |
    |                                  |       claim specifies        |
    |                                  |         {                    |
    |                                  |           id     : h'01',    |
    |                                  |           suite  : 2,        |
    |                                  |           methods: 3         |
    |                                  |         }                    |
    |                                  |                              |

 // Possibly after chain verification, the RS adds AUTH_CRED_C
 // to the set of its trusted peer authentication credentials,
 // relying on the AS as trusted provider

    |                                  |                              |
    |                                  |  2.01 (Created)              |
    |                                  |  (OSCORE-protected message)  |
M06 |                                  |<-----------------------------|
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M07 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by value        |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'token_uploaded' = true         |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'01',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
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
    |                                  |                              |
    |                                  |  Token upload to /authz-info |
    |                                  |  (OSCORE-protected message)  |
M14 |                                  |----------------------------->|
    |                                  |  In the access token:        |
    |                                  |     * the 'cnf' claim        |
    |                                  |       specifies AUTH_CRED_C  |
    |                                  |       by reference           |
    |                                  |     * the 'edhoc_params'     |
    |                                  |       claim specifies        |
    |                                  |         {                    |
    |                                  |           id     : h'05',    |
    |                                  |           suite  : 2,        |
    |                                  |           methods: 3         |
    |                                  |         }                    |
    |                                  |                              |
    |                                  |                              |
    |                                  |  2.01 (Created)              |
    |                                  |  (OSCORE-protected message)  |
M15 |                                  |<-----------------------------|
    |                                  |                              |
    |                                  |                              |
    |  Token response                  |                              |
    |  (OSCORE-protected message)      |                              |
M16 |<---------------------------------|                              |
    |  'rs_cnf' specifies              |                              |
    |     AUTH_CRED_RS by reference    |                              |
    |                                  |                              |
    |  'ace_profile' =                 |                              |
    |             coap_edhoc_oscore    |                              |
    |                                  |                              |
    |  'token_uploaded' = true         |                              |
    |                                  |                              |
    |  'edhoc_params' specifies:       |                              |
    |     {                            |                              |
    |       id     : h'05',            |                              |
    |       suite  : 2,                |                              |
    |       methods: 3                 |                              |
    |     }                            |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_1 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M17 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_2                 |                              |
    |  (no access control is enforced) |                              |
M18 |<----------------------------------------------------------------|
    |  ID_CRED_R specifies             |                              |
    |     CRED_R = AUTH_CRED_RS        |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  EDHOC message_3 to /edhoc       |                              |
    |  (no access control is enforced) |                              |
M19 |---------------------------------------------------------------->|
    |  ID_CRED_I identifies            |                              |
    |     CRED_I = AUTH_CRED_C         |                              |
    |     by reference                 |                              |
    |                                  |                              |
    |                                  |                              |
    |  Access to protected resource /r |                              |
    |  (OSCORE-protected message)      |                              |
    |  (access control is enforced)    |                              |
M20 |---------------------------------------------------------------->|
    |                                  |                              |
    |                                  |                              |
    |  Response                        |                              |
    |  (OSCORE-protected message)      |                              |
M21 |<----------------------------------------------------------------|
    |                                  |                              |
~~~~~~~~~~~~~~~~~~~~~~~

# Acknowledgments # {#acknowldegment}
{: numbered="no"}

Work on this document has in part been supported by the H2020 project SIFIS-Home (grant agreement 952652).
