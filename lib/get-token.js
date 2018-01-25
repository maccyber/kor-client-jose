const axios = require('axios')
const { stringify } = require('querystring')

module.exports = async options => {
  if (!options) {
    throw Error('Missing required input: options')
  }
  if (!options.url) {
    throw Error('Missing required input: options.url')
  }
  if (!options.jwt) {
    throw Error('Missing required input: options.jwt')
  }

  const payload = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: options.jwt
  }

  const httpOptions = {
    url: options.url,
    data: stringify(payload),
    headers: {
      'Content-type': 'application/x-www-form-urlencoded'
    },
    method: 'post'
  }

  try {
    const { data } = await axios(httpOptions)
    return data
  } catch (error) {
    throw error
  }
}
