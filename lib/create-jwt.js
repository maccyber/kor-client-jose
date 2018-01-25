const jose = require('node-jose')
const uuid = require('uuid/v1')

const certToX5c = cert => cert.replace(/-----[^\n]+\n?/gm, '').replace(/\n/g, '')

module.exports = async options => {
  if (!options) {
    throw Error('Missing required input: options')
  }
  if (!options.cert) {
    throw Error('Missing required input: options.cert')
  }
  if (!options.privateKey) {
    throw Error('Missing required input: options.privateKey')
  }
  if (!options.audience) {
    throw Error('Missing required input: options.audience')
  }
  if (!options.algorithm) {
    throw Error('Missing required input: options.algorithm')
  }
  if (!options.issuer) {
    throw Error('Missing required input: options.privateKey')
  }

  const keystore = jose.JWK.createKeyStore()
  const privateKey = await keystore.add(options.privateKey, 'pem')

  const payload = JSON.stringify({
    iss: options.issuer,
    aud: options.audience,
    exp: Date.now() + 120000,
    iat: Date.now(),
    scope: options.scope,
    jti: uuid()
  })

  const signOptions = { format: 'compact', alg: options.algorithm, fields: { x5c: certToX5c(options.cert) } }

  try {
    const signed = await jose.JWS.createSign(signOptions, privateKey).update(payload, 'utf8').final()
    return signed
  } catch (error) {
    throw error
  }
}
