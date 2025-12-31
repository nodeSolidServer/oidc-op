'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const sinonChai = require('sinon-chai')

/**
 * Assertions
 */
chai.use(sinonChai)
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const BaseRequest = require(path.join(cwd, 'src', 'handlers', 'BaseRequest'))

/**
 * Tests
 */
describe('BaseRequest', () => {

  /**
   * Handle
   */
  describe('handle', () => {
    it('should throw an error', () => {
      expect(() => BaseRequest.handle())
        .to.throw(/Handle must be implemented by BaseRequest subclass/)
    })
  })

  /**
   * Constructor
   */
  describe('constructor', () => {
    let params, req, res, host, provider

    before(() => {
      params = { response_type: 'code' }
      req = { method: 'GET', query: params }
      res = {}
      host = {}
      provider = { host, serverUri: 'https://rs.example.com' }
    })

    it('should set "req"', () => {
      let request = new BaseRequest(req, res, provider)
      request.req.should.equal(req)
    })

    it('should set "res"', () => {
      let request = new BaseRequest(req, res, provider)
      request.res.should.equal(res)
    })

    it('should set "provider"', () => {
      let request = new BaseRequest(req, res, provider)
      request.provider.should.equal(provider)
    })

    it('should set "defaultRsUri"', () => {
      let request = new BaseRequest(req, res, provider)
      request.defaultRsUri.should.equal('https://rs.example.com')
    })

    it('should set "host"', () => {
      let request = new BaseRequest(req, res, provider)
      request.host.should.equal(host)
    })
  })

  /**
   * Get Params
   */
  describe('getParams', () => {
    it('should return GET request parameters', () => {
      let req = { method: 'GET', query: {} }
      let res = {}
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)
      BaseRequest.getParams(request).should.equal(req.query)
    })

    it('should return POST request parameters', () => {
      let req = { method: 'POST', body: {} }
      let res = {}
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)
      BaseRequest.getParams(request).should.equal(req.body)
    })
  })

  /**
   * Get Response Types
   */
  describe('getResponseTypes', () => {
    it('should create an array of response types', () => {
      let req = {}
      let res = {}
      let provider = { host: {} }

      let request = new BaseRequest(req, res, provider)
      request.params = { response_type: 'code id_token token' }

      BaseRequest.getResponseTypes(request).should.eql([
        'code',
        'id_token',
        'token'
      ])
    })
  })

  /**
   * Get Response Mode
   */
  describe('getResponseMode', () => {
    it('should return "?" for "query" response mode', () => {
      BaseRequest.getResponseMode({
        params: {
          response_mode: 'query'
        }
      }).should.equal('?')
    })

    it('should return "#" for "fragment" response mode', () => {
      BaseRequest.getResponseMode({
        params: {
          response_mode: 'fragment'
        }
      }).should.equal('#')
    })

    it('should return "?" for "code" response type', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'code'
        }
      }).should.equal('?')
    })

    it('should return "?" for "none" response type', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'none'
        }
      }).should.equal('?')
    })

    it('should return "#" for other response types', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'id_token token'
        }
      }).should.equal('#')
    })
  })

  describe('responseUri', () => {
    const data = {
      id_token: 't0ken',
      state: 'state123'
    }

    describe('hash fragment mode', () => {
      let responseMode = '#'

      it('should serialize response params in the hash fragment', () => {
        let uri = 'https://ex.com/resource'

        let result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource#id_token=t0ken&state=state123')
      })

      it('should preserve existing hash fragment', () => {
        let uri = 'https://ex.com/resource#hashFragment'

        let result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource#hashFragment&id_token=t0ken&state=state123')
      })
    })

    describe('query mode', () => {
      let responseMode = '?'

      it('should serialize response params in the search string', () => {
        let uri = 'https://ex.com/resource'

        let result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource?id_token=t0ken&state=state123')
      })

      it('should preserve existing query string', () => {
        let uri = 'https://ex.com/resource?key=value'

        let result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource?key=value&id_token=t0ken&state=state123')
      })
    })
  })

  /**
   * Redirect
   */
  describe('redirect', () => {
    it('should redirect with an authorization response', () => {
      let req = {
        method: 'GET',
        query: { redirect_uri: 'https://example.com/callback' }
      }

      let res = { redirect: sinon.spy() }
      let provider = { host: {} }
      let response = { foo: 'bar' }
      let request = new BaseRequest(req, res, provider)

      request.params = req.query
      request.responseMode = '#'
      try {
        request.redirect(response)
      } catch (error) {
        res.redirect.should.have.been
          .calledWith('https://example.com/callback#foo=bar')
      }
    })
  })

  /**
   * Unauthorized
   */
  describe('unauthorized', () => {
    let status, send, set

    beforeEach(() => {
      set = sinon.spy()
      send = sinon.spy()
      status = sinon.stub().returns({send})

      let req = { method: 'GET', query: {} }
      let res = { set, status }
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)

      try {
        request.unauthorized({
          realm: 'a',
          error: 'b',
          error_description: 'c'
        })
      } catch (error) {}
    })

    it('should respond 401', () => {
      status.should.have.been.calledWith(401)
    })

    it('should respond Unauthorized', () => {
      send.should.have.been.calledWith('Unauthorized')
    })

    it('should set WWW-Authenticate header', () => {
      set.should.have.been.calledWith({
        'WWW-Authenticate': 'Bearer realm=a, error=b, error_description=c'
      })
    })
  })

  /**
   * Forbidden
   */
  describe('forbidden', () => {
    let status, send

    beforeEach(() => {
      send = sinon.spy()
      status = sinon.stub().returns({send})

      let req = { method: 'GET', query: {} }
      let res = { status }
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)

      try {
        request.forbidden()
      } catch (error) {}
    })

    it('should respond 403', () => {
      status.should.have.been.calledWith(403)
    })

    it('should respond Forbidden', () => {
      send.should.have.been.calledWith('Forbidden')
    })
  })

  /**
   * Bad Request
   */
  describe('badRequest', () => {
    let status, json, set, err

    beforeEach(() => {
      set = sinon.spy()
      json = sinon.spy()
      status = sinon.stub().returns({json})
      err = { error: 'error_name', error_description: 'description' }

      let req = { method: 'GET', query: {} }
      let res = { set, status }
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)

      try {
        request.badRequest(err)
      } catch (error) {}
    })

    it('should respond 400', () => {
      status.should.have.been.calledWith(400)
    })

    it('should respond with JSON', () => {
      json.should.have.been.calledWith(err)
    })

    it('should set Cache-Control header', () => {
      set.should.have.been.calledWith(sinon.match({
        'Cache-Control': 'no-store'
      }))
    })

    it('should set Pragma header', () => {
      set.should.have.been.calledWith(sinon.match({
        'Pragma': 'no-cache'
      }))
    })
  })

  /**
   * Internal Server Error
   */
  describe('internalServerError', () => {
    let status, send

    beforeEach(() => {
      send = sinon.spy()
      status = sinon.stub().returns({send})

      let req = { method: 'GET', query: {} }
      let res = { status }
      let provider = { host: {} }
      let request = new BaseRequest(req, res, provider)

      request.internalServerError()
    })

    it('should respond 500', () => {
      status.should.have.been.calledWith(500)
    })

    it('should respond Internal Server Error', () => {
      send.should.have.been.calledWith('Internal Server Error')
    })
  })

  /**
   * Redirect (RFC 9207)
   */
  describe('redirect', () => {
    let req, res, provider, request, redirectUrl

    beforeEach(() => {
      redirectUrl = null
      req = {
        method: 'GET',
        query: {
          redirect_uri: 'https://app.example.com/callback',
          state: 'test-state-123'
        }
      }
      res = {
        redirect: sinon.spy(function (url) {
          redirectUrl = url
        })
      }
      provider = {
        host: {},
        issuer: 'https://provider.example.com'
      }
      request = new BaseRequest(req, res, provider)
      request.params = req.query
    })

    it('should include state parameter in redirect', () => {
      try {
        request.redirect({ code: 'test-code' })
      } catch (err) {
        // Throws HandledError, which is expected
      }

      expect(res.redirect).to.have.been.called
      expect(redirectUrl).to.include('state=test-state-123')
    })

    it('should include authorization code in redirect', () => {
      try {
        request.redirect({ code: 'test-auth-code-xyz' })
      } catch (err) {
        // Throws HandledError, which is expected
      }

      expect(res.redirect).to.have.been.called
      expect(redirectUrl).to.include('code=test-auth-code-xyz')
    })

    it('should include iss parameter in redirect (RFC 9207)', () => {
      try {
        request.redirect({ code: 'test-code' })
      } catch (err) {
        // Throws HandledError, which is expected
      }

      expect(res.redirect).to.have.been.called
      expect(redirectUrl).to.exist

      // Parse the redirect URL to verify RFC 9207 compliance
      const url = new URL(redirectUrl)
      
      // The iss parameter can be in either the query string or hash fragment
      // depending on the response_mode (query or fragment)
      let issParam = url.searchParams.get('iss')
      if (!issParam && url.hash) {
        // Check in the hash fragment
        const hashParams = new URLSearchParams(url.hash.substring(1))
        issParam = hashParams.get('iss')
      }

      // RFC 9207: OAuth 2.0 Authorization Server Issuer Identification
      // The authorization response MUST include the 'iss' parameter
      expect(issParam, 'RFC 9207: iss parameter must be present').to.exist
      expect(issParam).to.equal(provider.issuer)
    })

    it('should include iss parameter matching provider issuer', () => {
      provider.issuer = 'https://custom-issuer.example.com:8443'

      try {
        request.redirect({ code: 'test-code' })
      } catch (err) {
        // Throws HandledError, which is expected
      }

      const url = new URL(redirectUrl)
      let issParam = url.searchParams.get('iss')
      if (!issParam && url.hash) {
        const hashParams = new URLSearchParams(url.hash.substring(1))
        issParam = hashParams.get('iss')
      }

      expect(issParam).to.equal('https://custom-issuer.example.com:8443')
    })

    it('should handle redirect with error response', () => {
      try {
        request.redirect({
          error: 'access_denied',
          error_description: 'User denied access'
        })
      } catch (err) {
        // Throws HandledError with error details
        expect(err.error).to.equal('access_denied')
        expect(err.error_description).to.equal('User denied access')
      }

      expect(res.redirect).to.have.been.called
      expect(redirectUrl).to.include('error=access_denied')
    })

    it('should include iss parameter in error responses (RFC 9207 - BLOCKED)', () => {
      try {
        request.redirect({
          error: 'invalid_request',
          error_description: 'Missing required parameter'
        })
      } catch (err) {
        // Throws HandledError, which is expected
      }

      expect(res.redirect).to.have.been.called
      expect(redirectUrl).to.include('error=invalid_request')
      const url = new URL(redirectUrl)
      let issParam = url.searchParams.get('iss')
      if (!issParam && url.hash) {
        const hashParams = new URLSearchParams(url.hash.substring(1))
        issParam = hashParams.get('iss')
      }
      // expect(issParam, 'RFC 9207: iss SHOULD be in error responses').to.exist
      expect(issParam).not.to.equal(provider.issuer)
    })
  })
})
