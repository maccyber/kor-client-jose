(async () => {
  const { readFileSync } = require('fs')
  const openIdClient = require('./index')

  const clientOptions = {
    url: 'https://oidc-ver1.difi.no/',
    cert: readFileSync('./data/public.pem', 'utf-8'),
    privateKey: readFileSync('./data/private.key', 'utf-8'),
    /* privateKeyPassphrase: 'password', // uncomment if privateKey is encrypted */
    issuer: 'Din-id',
    scope: 'global/kontaktinformasjon.read'
  }

  try {
    const client = await openIdClient(clientOptions)
    console.log(client)
  } catch (error) {
    console.error(error)
  }
})()
