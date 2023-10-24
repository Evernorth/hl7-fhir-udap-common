# hl7-fhir-udap-common

## Overview

This is nodejs library that is part of a 4 repo collection for a full [UDAP](https://www.udap.org/) implementation.   The implementation adheres to the published [HL7 UDAP Security Implementation Guide](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/).   The methods in this library are methods that will be used by both a UDAP Server and a UDAP Client.  The methods provide functionality that supports dealing with UDAP JWT's (creating and verifying), dealing with Trust Community Certificates (parsing, for signing keys, validating certficate chains, CRL and expiration).

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

The hl7-fhir-udap-common was developed originally as a collaborative effort between [Evernorth](https://www.evernorth.com/) and [OKTA](https://www.okta.com/).  We would like to recognize the following people for their initial contributions to the project: 
 - Tom Loomis - Evernorth
 - Dan Cinnamon - OKTA