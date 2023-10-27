# hl7-fhir-udap-common

## Overview

This is nodejs library that is part of a 4 repository collection for a full [UDAP](https://www.udap.org/) implementation.   The implementation adheres to the published version 1.0 of the [HL7 UDAP Security Implementation Guide](https://hl7.org/fhir/us/udap-security/).   The methods in this library are methods that will be used by both a UDAP Server and a UDAP Client.  The methods provide functionality that supports dealing with UDAP JWT's (creating and verifying), dealing with Trust Community Certificates (parsing for signing keys and Subject Alternative Name (SAN), validating certficate chains, CRL and certificate expiration).

## Public Methods
* ***parsePKCS12(pkcs12Filename, password)*** - Used to load a PKCS12 keystore for use in signing UDAP JWTs.

* ***parseTrustAnchorPEM(caTrustAnchorFilename)*** - Used to specify which community CA your implementation will trust. Mainly used when validating a JWT.

* ***verifyUdapJwtCommon(udapJwtString, caTrustAnchorObject)*** - Performs basic JWT validation, and ensures that the JWT is signed with a certificate that belongs to the trusted community (as defined by the parseTrustAnchorPEM method).

* ***generateUdapSignedJwt(jwtClaims, communityMemberCertAndPrivateKeyObject,signingAlg)*** - Mints a new JWT with provided claims, and signs it using the private key loaded with the parsePKCS12 method.

* ***getAllSansFromCert(cert)*** - Helper method to extract out the list of subject alternative names from a certificate.

* ***getPublicKeyJWKS(udapJwtString)*** - Helper method for obtaining a certificate in JWKS format - a common format used in OAuth2 flows.

* ***validateSanInCert(sanValue, cert)*** - A helper method to determine if a given subject alternative name is present in a certificate.

## Usage

To see example code you can browse the [hl7-fhir-udap-client](https://github.com/Evernorth/hl7-fhir-udap-client#readme) and [hl7-fhir-udap-server](https://github.com/Evernorth/hl7-fhir-udap-server#readme) repositories.

## Installation

Currently the repositories are set up for local installation.  Placing all 4 repositories under the same parent folder will allow the package.json local file references to be resolved accurately.  Eventually this repository will be an npm package.

## Getting help

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Getting involved

Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for info on how to get involved.

## License

hl7-fhir-udap-common is Open Source Software released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).

## Original Contributors

The hl7-fhir-udap-common was developed originally as a collaborative effort between [Evernorth](https://www.evernorth.com/) and [Okta](https://www.okta.com/).  We would like to recognize the following people for their initial contributions to the project: 
 - Tom Loomis - Evernorth
 - Dan Cinnamon - Okta