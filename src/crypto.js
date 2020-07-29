'use strict'

const { crypto } = require('@solid/jose')
const base64url = require('base64url')

/**
 * hashClaim
 *
 * @description
 * Create a hash for at_hash or c_hash claim
 *
 * @param {string} token
 * @param {string} hashLength
 *
 * @returns {Promise<string>}
 */
function hashClaim (value, hashLength) {
  if (value) {
    let alg = { name: `SHA-${hashLength}`}
    let octets = new Buffer(value, 'ascii')

    return crypto.subtle.digest(alg, new Uint8Array(octets)).then(digest => {
      let hash = Buffer.from(digest)
      let half = hash.slice(0, hash.byteLength / 2)
      return base64url(half)
    })
  }
}

/**
 * @param byteLen {number} Number of random bytes requested
 *
 * @returns {string} Random bytes, hex-encoded to string.
 */
function random (byteLen) {
  const value = crypto.getRandomValues(new Uint8Array(byteLen))
  return Buffer.from(value).toString('hex')
}

module.exports = {
  hashClaim,
  random
}
