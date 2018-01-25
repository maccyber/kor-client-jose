const discover = require('./lib/discover')
const createJwt = require('./lib/create-jwt')
const getToken = require('./lib/get-token')
const getData = require('./lib/get-data')

exports.discover = discover
exports.createJwt = createJwt
exports.getToken = getToken
exports.getData = getData

module.exports = async options => {
  if (!options) {
    throw Error('Missing required input: options')
  }
  if (!options.url) {
    throw Error('Missing required input: options.url')
  }
  if (!options.cert) {
    throw Error('Missing required input: options.cert')
  }
  if (!options.privateKey) {
    throw Error('Missing required input: options.privateKey')
  }
  if (!options.issuer) {
    throw Error('Missing required input: options.issuer')
  }
  if (!options.scope) {
    throw Error('Missing required input: options.scope')
  }

  let config = false
  try {
    config = await discover({ url: options.url })
    config.jwt = await createJwt({...options, audience: config.issuer, algorithm: config.id_token_signing_alg_values_supported[0]})
    config.token = await getToken({ url: config.token_endpoint, jwt: config.jwt })
  } catch (error) {
    throw error.response && error.response.data && error.response.data.error ? error.response.data : error
  }

  return {
    getConfig: () => config,
    getConfigParameter: param => config && config[param],
    refreshToken: () => false
  }
}
