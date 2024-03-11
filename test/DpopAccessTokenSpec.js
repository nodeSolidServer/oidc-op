'use strict';

/**
 * Test dependencies
 */
const chai = require('chai')
const fs = require('fs')
const path = require('path')
const { JWT } = require('@solid/jose')
const { random } = require('../src/crypto')
const crypto = require('node:crypto')
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
const DpopAccessToken = require('../src/DpopAccessToken')
const MemoryStore = require('./backends/MemoryStore');

/**
 * Dpop tests
 */
describe('DpopAccessToken', () => {
    const providerUri = 'https://example.com';
    let provider;

    before(function() {
        const configPath = path.join(__dirname, 'config', 'provider.json');
        const storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        provider = new Provider(storedConfig);
        provider.inject({ backend: new MemoryStore() });
        return provider.initializeKeyChain(provider.keys);
    })

    describe('issueForRequest function validation', () => {
        let subject = { _id: 'solidUser123'};
        let client = { 'client_id': 'solidClient123'};
        let request, response;
        let params = {};
        let scope = ['token'];
        const defaultResourceServerUri = "https://rs.example.com"

        describe('authentication requests', () => {

            let code;
            beforeEach(() => {
                request = { params, code, provider, client, subject, scope, defaultResourceServerUri }
                
                request.dpopJwk = {
                    "kty": "RSA",
                    "kid": "IlOPtWXUcpiPttmr-K7DmehzeRM",
                    "n": "qv2XCvfUfW0bG547B1xieE0-GN8xLuCdzGcIWsYMP-fn1vR2ptR7XOp_kW-etlxSDT2MVyzdXbG9eQCgeBk-Ajgbyn4AaFScJt9ibGyE-5hUvkSJRTP-jlJjlPniYsKcjEY3C-QzyRcEIHoOHOEuevIFwVvKNRgEVYyx3CmkmIXcfw35R1tORNjCec_NA6dawx_LPpS0endjNz2m_iijLquKenrsKSKVnBprfVtBh_myuNQD5CfhBnzZRmAUfr0PoVMDBb0r_rWaV1Q64zQWSeCql7CSWq4U8RNhogd0eCZOOv45plIUwoxkdNg0Rzkp-OEtKRLaHonJ_OZ_sxa8-w",
                    "e": "AQAB",
                    "use": "sig"
                }
                
                response = {}
            })

            it('should issue an access token', async () => {
                const res = await DpopAccessToken.issueForRequest(request, response);

                expect(res['token_type']).to.equal('DPoP');
                expect(res['expires_in']).to.equal(1209600);
                
                const token = JWT.decode(res['access_token'])
                // console.debug(token);
                expect(token.type).to.equal('JWS')
                expect(token.header.alg).to.equal('RS256')
                expect(token.payload.iss).to.equal(providerUri)
                expect(token.payload.sub).to.equal('solidUser123')
                expect(token.payload.jti).to.exist()
                expect(token.payload.scope).to.eql(['token'])
                expect(token.payload.aud).to.eql('solid')

            })
        })
    })
})