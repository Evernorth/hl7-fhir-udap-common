'use strict'
const forge = require('node-forge')
const pki = require('node-forge').pki
const asn1 = require('node-forge').asn1
const pkcs12 = require('node-forge').pkcs12
const njwt = require('njwt')
const { v4: uuidv4 } = require('uuid')
const fs = require('fs')
const axios = require('axios')
const udapCommonError = require('./udap-common-error')
const pem2jwk = require('pem-jwk').pem2jwk

//For CRL only
const asn1js = require('asn1js')
const pkijs = require('pkijs')
const pvutils = require('pvutils')

//PUBLIC METHODS
//This method is intended to be passed the contents of a PKCS12 encrypted keystore.
//It will decrypt the keystore, and return back an array of items needed for UDAP functions.
// Array Returned contains an array of entries listed below:
//var entry = {
//   'localKeyId': '',
//    'certChain': [],  = cert object from node-forge library
//    'privateKey': '',
//    'privateKeyPem': ''
//}
module.exports.parsePKCS12 = (pkcs12Filename, password) => {
    try {
        const fileContent = fs.readFileSync(pkcs12Filename, 'binary')
        var udapKeyStore = getCertsAndPrivKeysFromBinary(fileContent, password)
        return udapKeyStore
    }
    catch (e) {
        console.error("error parsing pkcs12 file.")
        console.error(e)
        throw new udapCommonError("error parsing pkcs12 file: " + e.message)
    }
}

//This method will take a filename of a UDAP Trust community CA certificate in PEM format, and load it into memory.
//returns certificate object from node-forge library
module.exports.parseTrustAnchorPEM = (caTrustAnchorFilename) => {
    try {
        const fileContent = fs.readFileSync(caTrustAnchorFilename, 'utf-8')
        return pki.certificateFromPem(fileContent)
    }
    catch (e) {
        console.error("error parsing trust anchor file.")
        console.error(e)
        throw new udapCommonError("error parsing trust anchor file: " + e.message)
    }
}

//Given a JWT- this method will validate to ensure:
//1. That the signature checks out
//2. That the JWT is signed by a cert that's part of our community
//3. That the cert is not revoked.
//4. That the JWT is not expired.
//5. That the JWT has basic claims within it.
//After invoking this, the client/server must verify other claims based upon the use case.
//udapJwtString is the JWT to validate in base64.
//caTrustAnchorObject is the community cert used by the implementation that we're validating against.
//returns the following Object:
//{
//    verifiedJwt - the verifiedJwt Object
//    verifiedJwtCertificate - node-forge Certificate Object
//}
module.exports.verifyUdapJwtCommon = async (udapJwtString, caTrustAnchorObject) => {
    var jwtCertObject;
    try {
        //Need to parse first to get cert from header for public key
        var ssJwtParts = udapJwtString.split(".")
        var ssJwtHead = Buffer.from(ssJwtParts[0], 'base64').toString('utf-8')
        console.debug('Token Header')
        console.debug(ssJwtHead)
        var objJwtHead = JSON.parse(ssJwtHead)

        //get x5c value
        var x5c64 = objJwtHead.x5c
        if (!x5c64) {
            throw new udapCommonError("x5c header is missing.")
        }

        //decode base64
        var x5c = forge.util.decode64(x5c64[0])
        //Deal with DER encoding
        var certAsn1 = asn1.fromDer(x5c)
        jwtCertObject = pki.certificateFromAsn1(certAsn1)

        //Get public key to verify JWT
        const jwtPublicKeyPEM = pki.publicKeyToPem(jwtCertObject.publicKey)

        //This verifies the JWT and signature
        //if JWT isn't valid bail
        var ssVerifiedJwt = njwt.verify(udapJwtString, jwtPublicKeyPEM, objJwtHead.alg)
    }
    catch (e) {
        //For Dynamic client registration this error should return invalid_software_statement
        console.error("JWT Verify Exception:")
        console.error(e)
        throw new udapCommonError("JWT Verify Exception:" + e.message);
    }
    try {

        //Ensure that the key used to sign the JWT is actually part of our community, and is not in the CRL.
        //Let's only do this check if the JWT signing passes first.
        await validateCertWithCrlAndCertChain(jwtCertObject, caTrustAnchorObject)

        return {
            verifiedJwt: ssVerifiedJwt,
            verifiedJwtCertificate: jwtCertObject
        }
    }
    catch (e) {
        //For Dynamic client registration this error should return unapproved_software_statement
        console.error("Certificate Validation Error: ")
        console.error(e)
        throw new udapCommonError("Certificate Validation Error: " + e.message);
    }
}

//Generates a JWT with the appropriate claims necessary for:
//A client to authenticate with a UDAP capable authz server.
//A client to generate a signed software statement to be used in dynamic client registration with a UDAP capable authz server.
//A server to properly advertise it's endpoints via signed metadata.
//The jwtClaims object will be different depending upon the use case, and are defined in the udap-client/udap-server libraries.
//The communityMemberCertAndPrivateKeyObject object will be the output of the parsePKCS12 method as defined above. It will be the UDAP community cert used by the implementation.
module.exports.generateUdapSignedJwt = (jwtClaims, communityMemberCertAndPrivateKeyObject,signingAlg) => {
    var token = njwt.create(jwtClaims, communityMemberCertAndPrivateKeyObject.privateKeyPem, signingAlg)
    //Gets the lowest level certificate in the chain, which should be the public key for this entry.
    const cert = communityMemberCertAndPrivateKeyObject.certChain[0]
    const derCert = pki.pemToDer(pki.certificateToPem(cert))
    const string64 = forge.util.encode64(derCert.getBytes())
    token.setHeader('x5c', [string64])
    token.setHeader('alg', signingAlg)
    var now = new Date().getTime()
    //This is set to the maximum allowed in the IG
    var exp = token.body.iat * 1000 + (5 * 60 * 1000)
    token.setExpiration(exp)
    token.setJti(uuidv4())
    token = token.compact()
    return token
}

//Helper function to get all of  the SANs from the cert passed in.
//cert = certificate object from node-forge library
module.exports.getAllSansFromCert = (cert) => {
    try {
        console.debug("Loaded public cert- SAN:")
        console.debug(cert.getExtension('subjectAltName').altNames[0].value)
        return cert.getExtension('subjectAltName').altNames
    }
    catch (e) {
        console.error("error SANS from cert:")
        console.error(e)
        throw new udapCommonError("error SANS from cert: " + e.message)
    }
}

//Helper function to return back the public key of a given inbound JWT in JWKS format.
module.exports.getPublicKeyJWKS = (udapJwtString) => {
    try {
      const ssJwtParts = udapJwtString.split(".")
      const ssJwtHead = Buffer.from(ssJwtParts[0], 'base64').toString('utf-8')
      const header = JSON.parse(ssJwtHead)
      const x5c = forge.util.decode64(header.x5c[0])
      const certAsn1 = asn1.fromDer(x5c)
      const certPublicKey = pki.certificateFromAsn1(certAsn1).publicKey
      const certPublicKeyPEM = pki.publicKeyToPem(certPublicKey)
      var jwkPublic = pem2jwk(certPublicKeyPEM)
      if(header.kid) {
          jwkPublic.kid = header.kid
      }
      return { keys: [jwkPublic] }
    }
    catch (e) {
        console.error("error getting public key JWKS")
        console.error(e)
        throw new udapCommonError("error getting public key JWKS: " + e.message)
    }
}

//Returns true if SAN value is in cert
// sanValue = string
// cert = certificate object from node-forge library
module.exports.validateSanInCert = (sanValue, cert) => {
    const allSans = this.getAllSansFromCert(cert)
    const foundSAN = allSans.filter(san => san.value == sanValue)

    if (foundSAN.length == 0) {
        return false
    }
    else {
        console.debug("Found SAN: " + foundSAN[0].value)
        return true
    }
}

//INTERNAL/PRIVATE METHODS

//Leverages the node-forge library to extract out the public/private key from the inbound PKCS12 file to be used by the rest of the UDAP client and/or server.
//There's nothing udap specific about this, it's just a good example of how to use the node-forge libraries.
//Returns certChain as array of node-forge cert objects, privateKey as node-forge privateKey object along with pem version
function getCertsAndPrivKeysFromBinary(pkcs12String, password) {
    const p12Asn1 = asn1.fromDer(pkcs12String)

    const certPkcs12 = pkcs12.pkcs12FromAsn1(p12Asn1, false, password)

    var entries = []
    //Collecting all of the PKCS12 entries into a single map.
    for (var sci = 0; sci < certPkcs12.safeContents.length; ++sci) {
        var entry = {
            'localKeyId': '',
            'certChain': [],
            'privateKey': '',
            'privateKeyPem': ''
        }

        var safeContents = certPkcs12.safeContents[sci]
        console.debug('safeContents ' + (sci + 1))
        for (var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
            var safeBag = safeContents.safeBags[sbi]
            console.debug('safeBag.type: ' + safeBag.type)
            if (safeBag.attributes.localKeyId) {
                const localKeyId = forge.util.bytesToHex(safeBag.attributes.localKeyId[0])
                console.debug('localKeyId: ' + localKeyId)

                var existingEntry = entries.filter(entry => entry.localKeyId === localKeyId)
                if (existingEntry.length > 0) {
                    entry = existingEntry[0]
                }

                if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                    console.debug('found private key')
                    entry.privateKey = safeBag.key
                    entry.privateKeyPem = pki.privateKeyToPem(safeBag.key)
                } else if (safeBag.type === forge.pki.oids.certBag) {
                    // this bag has a certificate
                    console.debug('found certificate')
                    entry.certChain.push(safeBag.cert)
                }
                if (existingEntry.length == 0) {
                    entry.localKeyId = localKeyId
                    entries.push(entry)
                }
            }
        }
    }
    return entries;
}

//This method will take the certificate used to sign the JWT, and then compare it with the community cert+chain to ensure it's valid.
async function validateCertWithCrlAndCertChain(udapJwtCertObject, caTrustAnchorObject) {
    // Validate cert is not on CRL
    try {
        await validateCrl(udapJwtCertObject, caTrustAnchorObject)
    }
    catch (e) {
        console.error("cert Expiration/Revocation Exception:")
        console.error(e)
        throw e
    }

    //Validate cert is part of our trust community.
    try {
        await validateCertChain(udapJwtCertObject, caTrustAnchorObject)
    }
    catch (e) {
        console.error("validateCertChain Exception:")
        console.error(e)
        throw e
    }

    return true
}

async function validateCrl(jwtCertObject, caTrustAnchorObject) {
    const distributionPoints = []

    //Internal method to deal with the different things we can see in the cRLDistributionPoints extension.
    const getDistributionPoints = (node) => {
        if (typeof node === 'string') {
            distributionPoints.push(node)
            return
        }
        if (Array.isArray(node)) {
            node.forEach(getDistributionPoints);
            return
        }
        if (node && typeof node === 'object') {
            getDistributionPoints(node.value)
        }
    }

    const ext = caTrustAnchorObject.getExtension('cRLDistributionPoints')
    getDistributionPoints(asn1.fromDer(ext.value))
    console.debug("Distribution Points: ")
    console.debug(distributionPoints)
    if (distributionPoints.length > 0) {
        for (var i = 0; i < distributionPoints.length; i++) {
            var crlUrl = distributionPoints[i]
            console.debug("CRL URL: " + crlUrl)
            try {
                const httpResponse = await axios.request({
                    'url': crlUrl,
                    'responseType': 'arraybuffer',
                    'method': 'get',
                    'headers': { 'Accept': 'application/x-x509-ca-cert' }
                })
                console.debug("CRL Response: ", httpResponse.data.toString())

                const buffer = new Uint8Array(httpResponse.data).buffer
                const asn1crl = asn1js.fromBER(buffer);
                const crl = new pkijs.CertificateRevocationList({
                    schema: asn1crl.result
                })

                for (let index in crl.revokedCertificates) {
                    var revokedCertificate = crl.revokedCertificates[index]
                    var revCertSerial = pvutils.bufferToHexCodes(revokedCertificate.userCertificate.valueBlock.valueHex)
                    console.debug("Cert Serial number: " + revCertSerial)
                    if (jwtCertObject.serialNumber.toLowerCase() == revCertSerial.toLowerCase()) {
                        console.debug("Cert on CRL:")
                        throw new Error("certificate revoked")
                    }
                }
            }
            catch (e) {
                console.error('Error validatating CRL:')
                console.error(e)
                throw e;
            }
        }
    }
    else {
        throw new Error("No CRL Found.")
    }
}

//This function performs in the following way:
//It will use the "cert" parameter, and it will determine if it's part of the chain matching the trust anchor designated by "caTrustAnchorObject".
//It will first fetch the chain at runtime, and then compare against the trust anchor.
async function validateCertChain(cert, caTrustAnchorObject) {
    console.debug("Inbound Cert to validate: ")
    console.debug(cert)

    console.debug("Trust Anchor to validate against: ")
    console.debug(caTrustAnchorObject)

    try {
        const caTrustAnchor = caTrustAnchorObject
        var caStore = pki.createCaStore()
        caStore.addCertificate(caTrustAnchor)

        const inboundCertChain = await getCertChain(cert)

        var chainVerified = pki.verifyCertificateChain(caStore, inboundCertChain)
        console.debug('Certificate chain verified: ', chainVerified)
    }
    catch (ex) {
        console.error("pki verifyCertificateChain Exception:")
        console.error(ex)
        console.error('Certificate chain verification error: ', chainVerified)
        throw ex
    }
}

//Gets the certificate chain from the inbound certificate used at runtime.
async function getCertChain(inboundCert) {
    const certChain = []
    var currentCert = inboundCert
    var parent = null
    do {
        certChain.push(currentCert)
        parent = currentCert.getExtension('authorityInfoAccess')
        if (parent != null) {
            //TODO:  Try to parse this like CRL sample .fromDer
            var parentUrl = parent.value.toString().split('\u0002')
            var parsePos = parentUrl[1].indexOf('http')
            var aiaUrl = parentUrl[1].substring(parsePos)
            console.debug("AIA Cert URI: " + aiaUrl)

            const httpResponse = await axios.request({
                'url': aiaUrl,
                'responseType': 'arraybuffer',
                'method': 'get',
                'headers': { 'Accept': 'application/x-x509-ca-cert' }
            })
            console.debug("1. HttpResponse  Data:")
            console.debug(httpResponse.data)
            if (httpResponse.data != null) {
                var cerDer = forge.util.createBuffer(httpResponse.data, 'raw')
                var asn1Cert = asn1.fromDer(cerDer)
                console.debug("AIA Cert: " + asn1.prettyPrint(asn1Cert))
                currentCert = pki.certificateFromAsn1(asn1Cert)
            }
            else {
                throw new Error('Could not retrieve cert: ' + httpResponse.statusCode)
            }

        }
        else {
            currentCert = parent
        }
    }
    while (currentCert != null)
    console.debug("2. Finished with chain")
    return certChain
}
