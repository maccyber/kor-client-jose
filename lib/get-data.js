const axios = require('axios')

module.exports = async options => {
  if (!options) {
    throw Error('Missing required input: options')
  }
  if (!options.url) {
    throw Error('Missing required input: options.url')
  }
  if (!options.token) {
    throw Error('Missing required input: options.token')
  }
  if (!options.payload) {
    throw Error('Missing required input: options.payload')
  }

  const httpOptions = {
    url: options.url,
    method: 'post',
    data: options.payload,
    headers: {
      Authorization: `Bearer ${options.token}`
    }
  }

  try {
    const { data } = await axios(httpOptions)
    return data
  } catch (error) {
    throw error
  }
}
