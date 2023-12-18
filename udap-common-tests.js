const common = require('./udap-common')


if(require.main === module) {
    main()
}

async function main() {
    const keyStore = common.parsePKCS12('', '')
    console.log("Final PKCS12 output:")
    console.log(keyStore)

    const trustAnchor = common.parseTrustAnchorPEM('ca.crt')
    console.log("Final Community Trust Anchor")
    console.log(trustAnchor)

    console.log("Generating a JWT with basic information")

    const testJwt = common.generateUdapSignedJwt({"test": "JWT"}, keyStore[0])

    console.log("JWT Returned:")
    console.log(testJwt)

    console.log("Validating the cert we just generated:")
    const validatedJWTDetails = await common.verifyUdapJwtCommon(testJwt, trustAnchor)
    console.log("JWT Details")
    console.log(validatedJWTDetails)
}