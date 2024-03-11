'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const fs = require('fs')
const path = require('path')
const { JWT } = require('@solid/jose')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('chai-as-promised'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../src/Provider')
const { random } = require('../src/crypto')
const DpopIDToken = require('../src/DpopIDToken')

/**
 * Tests
 */
describe('DpopIDToken', () => {
    const providerUri = 'https://example.com';
    let provider;

    before(function () {
        let configPath = path.join(__dirname, 'config', 'provider.json')

        let storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'))

        provider = new Provider(storedConfig);

        return provider.initializeKeyChain(provider.keys);
    })

  describe('issueForRequest()', () => {
    let code;
    let subject = { _id: 'user123' }
    let client;
    let request, response;
    let params, cnfKey;

    describe('authentication request', () => {
      beforeEach(() => {
        client = { 'client_id': 'client123' }
        params = { nonce: 'nonce123' }
        cnfKey = {
          'kty': 'RSA',
          'alg': 'RS256',
          'n': 'xykqKb0EPomxUR-W_4oXSqFVwEoD_ZdqSiFfYH-a9r8yGfmugq-fLEuuolQSqrzR3l9U0prBBUeICYBjfuTdRinhMbqkwm8R7_U6dptHe2yILYHLAl0oEooSDKaFMe90h7yDaWiahOewnhh4BWRc_KRNATqx0XGfVmj7Vt4QQifk_xJYZPbLClf8YJ20wKPSebfDzTdh6Jv3sM6ASo5-1PQJNqvk7Dy632E3zIqcQn8wRqQ3hDCJmX3uvMQ3oQNCpJDSvO1kuB0msMWwBwzq3QtUZcDjXovVpi2j3SZfc8X1nlh2H4hge3ATwb1az6IX_OQgn4r1UIsKqIUsTocIrw',
          'e': 'AQAB',
          'key_ops': [ 'verify' ],
          'ext': true
        }
        request = { params, code, provider, client, subject, cnfKey }
        response = {}
      })

      it('should issue an id token', () => {
        return DpopIDToken.issueForRequest(request, response)
          .then(res => {
            return JWT.decode(res['id_token'])
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.aud).to.equal('client123')
            expect(token.payload.azp).to.equal('client123')
            expect(token.payload.cnf).to.eql({ jwk: cnfKey })
          })
      })      



    })
  })
})