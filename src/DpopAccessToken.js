/**
 * Local dependencies
 */
const { JWT } = require('@solid/jose')
const { random } = require('./crypto')
const { jwkThumbprintByEncoding } = require('jwk-thumbprint')

const DEFAULT_MAX_AGE = 1209600  // Default Access token expiration, in seconds
const DEFAULT_SIG_ALGORITHM = 'RS256'

/**
 * DpopAccessToken
 */
class DpopAccessToken extends JWT {
  /**
   * issue
   *
   * Creates an access token issued by a given provider. Useful for integration
   * testing of client app code, to generate access tokens to pass along to
   * `supertest` http requests. Usage (in mocha `beforeEach()`, for example):
   *
   *   ```
   *   // This assumes you have a Provider instance, an RP Client id,
   *   // and a particular user in mind (for the `sub`ject claim)
   *
   *   let options = { aud: rpClientId, sub: userId, scope: 'openid profile' }
   *   let token = DpopAccessToken.issue(provider, options)

   *   return token.encode()
   *     .then(compactToken => {
   *       headers['Authorization'] = 'Bearer ' + compactToken
   *     })
   *   ```
   *
   * @param options {Object}
   *
   * Required:
   * @param provider {Provider} OIDC Identity Provider issuing the token
   * @param provider.issuer {string} Provider URI
   * @param provider.keys
   *
   * @param options.aud {string|Array<string>} Audience for the token
   *   (such as the Relying Party client_id)
   * @param options.sub {string} Subject id for the token (opaque, unique to
   *   the issuer)
   * @param options.scope {string} OAuth2 scope
   *
   * Optional:
   * @param [options.alg] {string} Algorithm for signing the access token
   * @param [options.jti] {string} Unique JWT id (to prevent reuse)
   * @param [options.iat] {number} Issued at timestamp (in seconds)
   * @param [options.max] {number} Max token lifetime in seconds
   *
   * @returns {JWT} Access token (JWT instance)
   */
  static issue (provider, options) {
    const { issuer, keys } = provider

    const { aud, sub, cnf } = options

    const alg = options.alg || DEFAULT_SIG_ALGORITHM
    const jti = options.jti || random(8)
    const iat = options.iat || Math.floor(Date.now() / 1000)
    const max = options.max || DEFAULT_MAX_AGE
    const scope = options.scope || ['token'] //idk if this is right
    const exp = iat + max  // token expiration

    const iss = issuer
    const key = keys.token.signing[alg].privateKey
    const kid = keys.token.signing[alg].publicJwk.kid

    const webid = sub;
    const client_id = aud;

    const header = { alg, kid }
    const payload = {
      iss,
      aud: "solid",
      sub,
      exp,
      iat,
      jti,
      cnf,
      client_id,
      webid,
      scope
    }

    const jwt = new DpopAccessToken({ header, payload, key })
    
    return jwt
  }

  /**
   * issue
   */
  static issueForRequest (request, response) {
    const { params, code, provider, client, subject, defaultRsUri } = request

    const alg = client['access_token_signed_response_alg'] || DEFAULT_SIG_ALGORITHM
    const jti = random(8)
    const iat = Math.floor(Date.now() / 1000)
    let aud, sub, max, scope

    // authentication request
    if (!code) {
      aud = client['client_id']
      sub = subject['_id']
      max = parseInt(params['max_age']) || client['default_max_age'] || DEFAULT_MAX_AGE
      scope = request.scope

    // token request
    } else {
      aud = code.aud
      sub = code.sub
      max = parseInt(code['max']) || client['default_max_age'] || DEFAULT_MAX_AGE
      scope = code.scope
    }

    const cnf = {
      jkt: jwkThumbprintByEncoding(request.dpopJwk, "SHA-256", 'base64url')
    }

    const options = { aud, sub, scope, alg, jti, iat, max, cnf }
    // console.debug(options)
    let header, payload

    return Promise.resolve()
      .then(() => DpopAccessToken.issue(provider, options))
      .then(jwt => {
        header = jwt.header
        payload = jwt.payload

        return jwt.encode()
      })
      // set the response properties
      .then(compact => {
        response['access_token'] = compact
        response['token_type'] = 'DPoP'
        response['expires_in'] = max
      })
      // store access token by "jti" claim
      .then(() => {
        return provider.backend.put('tokens', `${jti}`, { header, payload })
      })
      // store access token by "refresh_token", if applicable
      .then(() => {
        let responseTypes = request.responseTypes || []
        let refresh

        if (code || responseTypes.includes('code')) {
          refresh = random(16)
        }

        if (refresh) {
          response['refresh_token'] = refresh
          return provider.backend.put('refresh', `${refresh}`, { header, payload })
        }
      })
      // resolve the response
      .then(() => response)
  }
}

DpopAccessToken.DEFAULT_MAX_AGE = DEFAULT_MAX_AGE
DpopAccessToken.DEFAULT_SIG_ALGORITHM = DEFAULT_SIG_ALGORITHM

/**
 * Export
 */
module.exports = DpopAccessToken
