const jose = require('jose');


// need checks to make sure alg is a valid pub key crypto scheme
async function generateDpopJWT(alg, jwk, htm, htu, jti, privKey, duration, ath, nonce) {
    if (jti === undefined) {
        jti = 'random'
    }
    if (alg === undefined) {
        alg = 'RS256'
    }
    if (jwk === undefined) {
        jwk = await jose.importJWK({
            kty: 'RSA',
            e: 'AQAB',
            n: '12oBZRhCiZFJLcPg59LkZZ9mdhSMTKAQZYq32k_ti5SBB6jerkh-WzOMAO664r_qyLkqHUSp3u5SbXtseZEpN3XPWGKSxjsy-1JyEFTdLSYe6f9gfrmxkUF_7DTpq0gn6rntP05g2-wFW50YO7mosfdslfrTJYWHFhJALabAeYirYD7-9kqq9ebfFMF4sRRELbv9oi36As6Q9B3Qb5_C1rAzqfao_PCsf9EPsTZsVVVkA5qoIAr47lo1ipfiBPxUCCNSdvkmDTYgvvRm6ZoMjFbvOtgyts55fXKdMWv7I9HMD5HwE9uW839PWA514qhbcIsXEYSFMPMV6fnlsiZvQQ',
            },
            'RS256',
        )
    }
    if (duration === undefined) {
        duration = "10 minutes"
    }
    if (privKey === undefined) {
        const kp = await jose.generateKeyPair('RS256');
        privKey = kp.privateKey
    }
    let body = {
        htm,
        htu
    }
    if (ath) {
        body = Object.assign(body, { ath })
    }
    if (nonce) {
        body = Object.assign(body, { nonce })
    }
    const jwt = new jose.SignJWT(body)
        .setProtectedHeader({
            typ: 'dpop+jwt',
            alg,
            jwk
        })
        .setIssuedAt()
        .setAudience('solid')
        .setJti(jti)
        .setExpirationTime(duration)
        .sign(privKey)
        
    return jwt
}

// following https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
//  Step 1 - There is not more than one DPoP HTTP request header field
//  Step 1 is out of scope of this function.
//  Step 2 - The Dpop HTTP request header field value is a single and well-formed JWT
//  Step 2 is out of scope of this function.
function verifyDpop(jwt, method, nonce) {
    const dpopBody = jose.decodeJwt(jwt)
    const dpopHeader = jose.decodeProtectedHeader(jwt)
    // step 3
    if (!validateDpopBody(dpopBody)) {
        throw new Error('dpop validation failed')
    }
    // step 4
    if (!headerIsDpopAndJwt(dpopHeader)) {
        throw new Error('dpop validation failed')
    }
    // step 5
    if (!algIsSupported(dpopHeader.alg)) {
        throw new Error('dpop validation failed')
    }
    // step 6
    try {
        jose.jwtVerify(jwt, dpopHeader.jwk)
    } catch (err) {
        throw new Error(`jwt validation failed: ${err.message}`)
    }
    // step 7
    // not sure how to handle this
    // step 8
    if (!validateHtm(method, dpopBody.htm)) {
        throw new Error('dpop validation failed')
    }
    // step 9
    if (!validateHtu(uri, dpopBody.htu)) {
        throw new Error('dpop validation failed')
    }
    // step 10
    if (nonce) {
        if (!validateNonce(nonce, dpopBody.nonce)) {
            throw new Error('dpop validation failed')
        }
    }
    // step 11
    if (!validateIssueTime(dpopBody.iat, window)) {
        throw new Error('dpop validation failed')
    }
    // step 12
    // probably need extra stuff for step 12, or in separate function
}   

// https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
// Step 3
function validateDpopBody(dpopBody, requiresAth, requiresNonce) {
    let result = dpopBody.jti && dpopBody.htm && dpopBody.htu && dpopBody.iat
    if (requiresAth) {
        result = result && dpopBody.ath
    }
    if (requiresNonce) {
        result = result && dpopBody.nonce
    }
    return result
}

// https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
// Step 4
function headerIsDpopAndJwt(dpopHeader) {
    return dpopHeader.typ === 'dpop+jwt'
}

// https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
// Step 5
VALID_ALGS = ['RS256', 'ES256']
function algIsSupported(alg) {
    return VALID_ALGS.includes(alg)
}

// https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
// Step 8
function validateHtm(method, htm) {
    return method === htm
}

// https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax
// Step 9
function validateHtu(url, htu) {
    return url === normalizeHtu(htu)
}

function normalizeHtu(htu) {
    // remove fragment parts
    if (htu.includes('#')) {
        htu = htu.split('#')[0]
    }
    if (htu.includes('?')) {
        htu = htu.split('?')[0]
    }
    return htu
}


// Step 10
function validateNonce(serverNonce, dpopNonce) {
    return serverNonce === dpopNonce
}

// Step 11
function validateIssueTime(iat, window) {
    return iat < (iat + window) && iat > (iat - window)
}


module.exports = {
    generateDpopJWT
}