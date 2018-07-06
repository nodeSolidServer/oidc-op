'use strict'

const chai = require('chai')
const expect = chai.expect
const sinon = require('sinon')
const sinonChai = require('sinon-chai')
chai.use(require('dirty-chai'))
chai.use(sinonChai)
chai.should()
const HttpMocks = require('node-mocks-http')

const RPInitiatedLogoutRequest = require('../../src/handlers/RPInitiatedLogoutRequest')
const IDToken = require('../../src/IDToken')

const provider = {
  host: {
    logout: () => {},
    defaults: {
      post_logout_redirect_uri: '/goodbye'
    }
  }
}

async function issueIdToken (oidcProvider) {
  const jwt = IDToken.issue(oidcProvider, {
    sub: 'user123',
    aud: 'https://op.example.com',
    azp: 'client123'
  })

  return jwt.encode()
}

const postLogoutRedirectUri = 'https://rp.example.com/goodbye'
const reqNoParams = HttpMocks.createRequest({ method: 'GET', params: {} })
const reqWithParams = HttpMocks.createRequest({
  method: 'GET',
  query: {
    'id_token_hint': {},
    'state': 'abc123',
    'post_logout_redirect_uri': postLogoutRedirectUri
  }
})

describe('RPInitiatedLogoutRequest', () => {
  describe('handle()', () => {
    it('should invoke injected host.logout', () => {
      let res = HttpMocks.createResponse()
      let logoutSpy = sinon.stub(provider.host, 'logout').resolves()

      return RPInitiatedLogoutRequest.handle(reqNoParams, res, provider)
        .then(() => {
          expect(logoutSpy).to.have.been.called()
        })
    })
  })

  describe('constructor()', () => {
    it('should parse the incoming request params', () => {
      let res = {}
      let request = new RPInitiatedLogoutRequest(reqWithParams, res, provider)

      expect(request).to.have.property('params')
      expect(Object.keys(request.params).length).to.equal(3)
      expect(request.params.state).to.equal('abc123')
    })
  })

  describe('validate()', () => {
    it('should validate the `id_token_hint` param')
    it('should validate that `post_logout_redirect_uri` has been registered')
  })

  describe('redirectToGoodbye()', () => {
    it('should redirect to RP if logout uri provided', () => {
      let res = HttpMocks.createResponse()
      let req = HttpMocks.createRequest({
        method: 'GET',
        query: {
          'post_logout_redirect_uri': postLogoutRedirectUri,
          'state': '$tate'
        }
      })
      let request = new RPInitiatedLogoutRequest(req, res, provider)

      request.redirectToGoodbye()

      expect(res.statusCode).to.equal(302)
      expect(res._getRedirectUrl())
        .to.equal(postLogoutRedirectUri + '?state=%24tate')
    })

    it('should redirect to host default if no RP logout uri provided', () => {
      let res = HttpMocks.createResponse()
      let request = new RPInitiatedLogoutRequest(reqNoParams, res, provider)

      request.redirectToGoodbye()

      expect(res.statusCode).to.equal(302)
      expect(res._getRedirectUrl())
        .to.equal(provider.host.defaults.post_logout_redirect_uri)
    })
  })
})
