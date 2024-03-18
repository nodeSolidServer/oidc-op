'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const fs = require('fs')
const path = require('path')
const { JWT } = require('@solid/jose')
const { generateDpopJWT } = require('../src/utils/dpopUtils')
const { decodeJwt, decodeProtectedHeader } = require('jose')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('chai-as-promised'))
chai.should()
let expect = chai.expect


describe('Dpop token validation functions', () => {
    it('should create a new signed JWT', async () => {

        const jwt = await generateDpopJWT()
        expect(jwt).to.not.be.null
        
        const decodedJwt = decodeJwt(jwt)
        expect(decodedJwt.aud).to.be.equal('solid')
        expect(decodedJwt.jti).to.be.equal('random')

        const decodedHeader = decodeProtectedHeader(jwt)
        expect(decodedHeader.typ).to.be.equal('dpop+jwt')
        expect(decodedHeader.alg).to.be.equal('RS256')
    })

    it('should created a signed JWT with nonce and ath', async () => {
        const ath = 'athclaim'
        const htm = 'htmclaim'
        const htu = 'htuclaim'
        const nonce = 'nonceclaim'
        const jwt = await generateDpopJWT(
            undefined,
            undefined,
            htm,
            htu,
            undefined,
            undefined,
            undefined,
            ath,
            nonce
        )

        const decodedJwt = decodeJwt(jwt)
        expect(decodedJwt.aud).to.be.equal('solid')
        expect(decodedJwt.jti).to.be.equal('random')
        expect(decodedJwt.ath).to.be.equal(ath)
        expect(decodedJwt.htm).to.be.equal(htm)
        expect(decodedJwt.htu).to.be.equal(htu)
        expect(decodedJwt.nonce).to.be.equal(nonce)
        

        const decodedHeader = decodeProtectedHeader(jwt)
        expect(decodedHeader.typ).to.be.equal('dpop+jwt')
        expect(decodedHeader.alg).to.be.equal('RS256')
    })

    context('verify dpop token', () => {
        it('should validate the DPoP token', () => {
            
        })
    })
})