/**
 * ES256 Support Tests for OIDC Provider
 * Tests that ES256/384/512 (ECDSA) algorithms work correctly for ID token signing
 */
'use strict'

const chai = require('chai')
const expect = chai.expect

const OIDCProvider = require('../src/Provider')
const IDToken = require('../src/IDToken')
const providerConfig = require('./config/provider')

describe('ES256 Algorithm Support', () => {
  let provider

  before(() => {
    // Initialize provider with test configuration that includes ES256
    return OIDCProvider.from(providerConfig).then(result => {
      provider = result
    })
  })

  describe('Provider configuration', () => {
    it('should include ES256 in id_token_signing_alg_values_supported', () => {
      expect(provider.id_token_signing_alg_values_supported).to.include('ES256')
    })

    it('should include ES384 in id_token_signing_alg_values_supported', () => {
      expect(provider.id_token_signing_alg_values_supported).to.include('ES384')
    })

    it('should include ES512 in id_token_signing_alg_values_supported', () => {
      expect(provider.id_token_signing_alg_values_supported).to.include('ES512')
    })

    it('should have ES256 key descriptor in keychain', () => {
      expect(provider.keys.descriptor.id_token.signing.ES256).to.exist
      expect(provider.keys.descriptor.id_token.signing.ES256.alg).to.equal('ES256')
      expect(provider.keys.descriptor.id_token.signing.ES256.namedCurve).to.equal('P-256')
    })

    it('should have ES384 key descriptor in keychain', () => {
      expect(provider.keys.descriptor.id_token.signing.ES384).to.exist
      expect(provider.keys.descriptor.id_token.signing.ES384.alg).to.equal('ES384')
      expect(provider.keys.descriptor.id_token.signing.ES384.namedCurve).to.equal('P-384')
    })

    it('should have ES512 key descriptor in keychain', () => {
      expect(provider.keys.descriptor.id_token.signing.ES512).to.exist
      expect(provider.keys.descriptor.id_token.signing.ES512.alg).to.equal('ES512')
      expect(provider.keys.descriptor.id_token.signing.ES512.namedCurve).to.equal('P-521')
    })

    it('should have ES256 keys in id_token signing keys', () => {
      expect(provider.keys.id_token.signing.ES256).to.exist
      expect(provider.keys.id_token.signing.ES256.privateJwk).to.exist
      expect(provider.keys.id_token.signing.ES256.publicJwk).to.exist
      expect(provider.keys.id_token.signing.ES256.privateJwk.kty).to.equal('EC')
      expect(provider.keys.id_token.signing.ES256.privateJwk.crv).to.equal('P-256')
      expect(provider.keys.id_token.signing.ES256.privateJwk.d).to.exist // private key component
    })

    it('should have ES256 public keys in JWKS', () => {
      const es256Keys = provider.keys.jwks.keys.filter(key => key.alg === 'ES256' && key.kty === 'EC')
      expect(es256Keys.length).to.be.at.least(1)
      expect(es256Keys[0].crv).to.equal('P-256')
      expect(es256Keys[0].x).to.exist
      expect(es256Keys[0].y).to.exist
      expect(es256Keys[0].d).to.not.exist // public key should not have private component
    })
  })

  describe('ID Token signing with ES256', () => {
    it('should issue an ID token signed with ES256', () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123',
        alg: 'ES256'
      }

      const token = IDToken.issue(provider, params)
      expect(token).to.be.an.instanceof(IDToken)
      expect(token.header.alg).to.equal('ES256')
      expect(token.header.kid).to.exist
      expect(token.payload.iss).to.equal(provider.issuer)
      expect(token.payload.sub).to.equal('user123')
    })

    it('should issue an ID token signed with ES384', () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123',
        alg: 'ES384'
      }

      const token = IDToken.issue(provider, params)
      expect(token).to.be.an.instanceof(IDToken)
      expect(token.header.alg).to.equal('ES384')
    })

    it('should issue an ID token signed with ES512', () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123',
        alg: 'ES512'
      }

      const token = IDToken.issue(provider, params)
      expect(token).to.be.an.instanceof(IDToken)
      expect(token.header.alg).to.equal('ES512')
    })

    it('should encode an ES256-signed ID token', async () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123',
        alg: 'ES256'
      }

      const token = IDToken.issue(provider, params)
      const encoded = await token.encode()
      
      expect(encoded).to.be.a('string')
      const parts = encoded.split('.')
      expect(parts).to.have.lengthOf(3)
      
      // Decode and verify
      const payloadB64 = parts[1]
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString())
      expect(payload.iss).to.equal(provider.issuer)
      expect(payload.sub).to.equal('user123')
    })
  })


  describe('Backward compatibility', () => {
    it('should still support RS256 (default)', () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123'
        // No alg specified, should default to RS256
      }

      const token = IDToken.issue(provider, params)
      expect(token).to.be.an.instanceof(IDToken)
      expect(token.header.alg).to.equal('RS256')
    })

    it('should support explicit RS256', () => {
      const params = {
        aud: 'https://example.com',
        sub: 'user123',
        nonce: 'abc123',
        alg: 'RS256'
      }

      const token = IDToken.issue(provider, params)
      expect(token).to.be.an.instanceof(IDToken)
      expect(token.header.alg).to.equal('RS256')
    })
  })
})
