'use strict'

/**
 * Dependencies
 */
const url = require('url')
const KeyChain = require('@solid/keychain')
const AuthenticationRequest = require('./handlers/AuthenticationRequest')
const OpenIDConfigurationRequest = require('./handlers/OpenIDConfigurationRequest')
const DynamicRegistrationRequest = require('./handlers/DynamicRegistrationRequest')
const JWKSetRequest = require('./handlers/JWKSetRequest')
const TokenRequest = require('./handlers/TokenRequest')
const UserInfoRequest = require('./handlers/UserInfoRequest')
const RPInitiatedLogoutRequest = require('./handlers/RPInitiatedLogoutRequest')

const DEFAULT_RESPONSE_TYPES_SUPPORTED = [
  'code',
  'code token',
  'code id_token',
  'id_token code',
  'id_token',
  'id_token token',
  'code id_token token',
  'none'
]
const DEFAULT_RESPONSE_MODES_SUPPORTED = [
  'query',
  'fragment'
]
const DEFAULT_GRANT_TYPES_SUPPORTED = [
  'authorization_code',
  'implicit',
  'refresh_token',
  'client_credentials'
]
const DEFAULT_SCOPES_SUPPORTED = [
  'openid',
  'offline_access'
]
const DEFAULT_SUBJECT_TYPES_SUPPORTED = ['public']

const DEFAULT_TOKEN_TYPES_SUPPORTED = ['legacyPop', 'dpop']

/**
 * OpenID Connect Provider
 */
class Provider {

  /**
   * constructor
   */
  constructor (data = {}) {
    const { issuer } = data
    if (!issuer) {
      throw new Error('OpenID Provider must have an issuer.')
    }

    this.issuer = data.issuer
    this.jwks_uri = data.jwks_uri
    this.scopes_supported = data.scopes_supported ||
      DEFAULT_SCOPES_SUPPORTED
    this.response_types_supported = data.response_types_supported ||
      DEFAULT_RESPONSE_TYPES_SUPPORTED
    this.token_types_supported = data.token_types_supported ||
      DEFAULT_TOKEN_TYPES_SUPPORTED
    this.response_modes_supported = data.response_modes_supported ||
      DEFAULT_RESPONSE_MODES_SUPPORTED
    this.grant_types_supported = data.grant_types_supported ||
      DEFAULT_GRANT_TYPES_SUPPORTED
    this.subject_types_supported = data.subject_types_supported ||
      DEFAULT_SUBJECT_TYPES_SUPPORTED
    this.id_token_signing_alg_values_supported =
      data.id_token_signing_alg_values_supported || ['RS256']
    this.id_token_encryption_alg_values_supported =
      data.id_token_encryption_alg_values_supported
    this.id_token_encryption_enc_values_supported =
      data.id_token_encryption_enc_values_supported
    this.userinfo_signing_alg_values_supported =
      data.userinfo_signing_alg_values_supported
    this.userinfo_encryption_alg_values_supported =
      data.userinfo_encryption_alg_values_supported
    this.userinfo_encryption_enc_values_supported =
      data.userinfo_encryption_enc_values_supported
    this.request_object_signing_alg_values_supported =
      data.request_object_signing_alg_values_supported
    this.request_object_encryption_alg_values_supported =
      data.request_object_encryption_alg_values_supported
    this.request_object_encryption_enc_values_supported =
      data.request_object_encryption_enc_values_supported
    this.token_endpoint_auth_methods_supported =
      data.token_endpoint_auth_methods_supported || ['client_secret_basic']
    this.token_endpoint_auth_signing_alg_values_supported =
      data.token_endpoint_auth_signing_alg_values_supported || ['RS256']
    this.display_values_supported = data.display_values_supported || []
    this.claim_types_supported = data.claim_types_supported || ['normal']
    this.claims_supported = data.claims_supported || []
    this.service_documentation = data.service_documentation
    this.claims_locales_supported = data.claims_locales_supported
    this.ui_locales_supported = data.ui_locales_supported
    this.claims_parameter_supported = data.claims_parameter_supported || false
    this.request_parameter_supported = data.request_parameter_supported
    if (this.request_parameter_supported === undefined) {
      this.request_parameter_supported = true
    }
    this.request_uri_parameter_supported = data.request_uri_parameter_supported || false
    this.require_request_uri_registration = data.require_request_uri_registration || false
    this.op_policy_uri = data.op_policy_uri
    this.op_tos_uri = data.op_tos_uri
    this.check_session_iframe = data.check_session_iframe
    this.end_session_endpoint = data.end_session_endpoint

    this.authorization_endpoint = data['authorization_endpoint'] || url.resolve(issuer, '/authorize')
    this.token_endpoint = data['token_endpoint'] || url.resolve(issuer, '/token')
    this.userinfo_endpoint = data['userinfo_endpoint'] || url.resolve(issuer, '/userinfo')
    this.jwks_uri = data['jwks_uri'] || url.resolve(issuer, '/jwks')
    this.registration_endpoint = data['registration_endpoint'] || url.resolve(issuer, '/register')
    this.check_session_iframe = data['check_session_iframe'] || url.resolve(issuer, '/session')
    this.end_session_endpoint = data['end_session_endpoint'] || url.resolve(issuer, '/logout')

  }

  /**
   * from
   *
   * @description
   * Factory method, resolves with a Provider instance, initialized from the
   * provided serialized provider `data`.
   * If data includes an exported JWK Set, the provider's keychain is imported,
   * otherwise, a new keychain is generated.
   *
   * @param data {Object} Parsed JSON of a serialized Provider
   *
   * @returns {Promise<Provider>}
   */
  static async from (data) {
    const provider = new Provider(data)

    await provider.initializeKeyChain(provider.keys)

    return provider
  }

  /**
   * initializeKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  initializeKeyChain (data) {
    if (!data) {
      return this.generateKeyChain()
    }

    return this.importKeyChain(data)
  }

  /**
   * generateKeyChain
   */
  generateKeyChain () {
    const modulusLength = 2048

    const descriptor = {
      id_token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {
          // ?
        }
      },
      token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {}
      },
      userinfo: {
        encryption: {}
      },
      register: {
        signing: {
          RS256: { alg: 'RS256', modulusLength }
        }
      }
    }

    this.keys = new KeyChain(descriptor)
    return this.keys.rotate()
  }

  /**
   * importKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  importKeyChain (data) {
    if (!data) {
      return Promise.reject(new Error('Cannot import empty keychain'))
    }

    return KeyChain.restore(data)
      .then(keychain => {
        this.keys = keychain

        return this
      })
  }

  /**
   * openidConfiguration
   */
  get openidConfiguration () {
    return JSON.stringify(this, (key, value) => key !== "keys" ? value : undefined)
  }

  /**
   * jwkSet
   */
  get jwkSet () {
    return this.keys.jwkSet
  }

  /**
   * inject
   */
  inject (properties) {
    Object.keys(properties).forEach(key => {
      const value = properties[key]

      Object.defineProperty(this, key, {
        enumerable: false,
        value
      })
    })
  }

  /**
   * Authorize
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  authorize (req, res) {
    AuthenticationRequest.handle(req, res, this)
  }

  /**
   * Logout
   *
   * Bound to the OP's `end_session_endpoint` uri
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   */
  logout (req, res) {
    RPInitiatedLogoutRequest.handle(req, res, this)
  }

  /**
   * Discover
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  discover (req, res) {
    OpenIDConfigurationRequest.handle(req, res, this)
  }

  /**
   * JWKs
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  jwks (req, res) {
    JWKSetRequest.handle(req, res, this)
  }

  /**
   * Register
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  register (req, res) {
    DynamicRegistrationRequest.handle(req, res, this)
  }

  /**
   * Token
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  token (req, res) {
    TokenRequest.handle(req, res, this)
  }

  /**
   * UserInfo
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  userinfo (req, res) {
    UserInfoRequest.handle(req, res, this)
  }
}

/**
 * Export
 */
module.exports = Provider
