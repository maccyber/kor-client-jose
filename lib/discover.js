const axios = require('axios')

const getDiscoveryUrl = url => {
  const DISCOVERY_PATH = '/.well-known/openid-configuration'
  const removeTrailingSlash = url => url.replace(/\/$/, '')
  url = removeTrailingSlash(url)
  const wellKnownUrl = url.endsWith(DISCOVERY_PATH) ? url : `${url}${DISCOVERY_PATH}`
  return wellKnownUrl
}

const validatePaths = data => {
  if (!data) {
    throw Error('Empty iodc response')
  }
  if (!data.issuer) {
    throw Error('No issuer found in iodc response')
  }
  if (!data.token_endpoint) {
    throw Error('No token endpoint found in iodc reponse')
  }
  if (!data.id_token_signing_alg_values_supported) {
    throw Error('No supported signing algorithms in iodc reponse')
  }
  return data
}

module.exports = async options => {
  if (!options) {
    throw Error('Missing required input: options')
  }
  if (!options.url) {
    throw Error('Missing required input: options.url')
  }

  const url = getDiscoveryUrl(options.url)
  try {
    const { data } = await axios.get(url)
    return validatePaths(data)
  } catch (error) {
    throw error
  }
}
