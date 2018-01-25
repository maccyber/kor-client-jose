# WIP - Kontakt- og Reservasjonsregisteret klient

[Node.js](https://nodejs.org/en/) klient for kontakt- og reservasjonsregisterets Oauth2-API (Server-til-server) - [mer info](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_api_krr.html)

Denne klienten benytter [node-jose](https://github.com/cisco/node-jose) for generering av JWT.

Programflyt
1. Kjører discover av angitt URL, og henter informasjon fra ***<URL>/.well-known/openid-configuration***
2. Lager JWT-token med sertifikat, og signerer med privat nøkkel
3. Sender http-forespørsel med JWT for å hente token

## Installasjon

```bash
git clone https:/github.com/maccyber/kor-client-jose
npm i
node tst.js
```

## Test klient

Endre evt klient-innstillinger i [tst.js](tst.js)

Legg inn ditt sertifikat og privatnøkkel i `data/`

Start med `node tst.js`

## Client options

| Parameter     | Verdi       |
| ------------- |-------------|
| url           | URL - f.eks. https://oidc-ver1.difi.no/ |
| cert          | Virksomhetssertifikat i PEM-format |
| privateKey    | Privat nøkkel til virksomhetssertifikat |
| privateKeyPassphrase (valgfri) | Passord for å dekryptere privat nøkkel |
| issuer        | client ID som er registert hos ID-porten OIDC-provider |
| scope         | Scope som klient forespør tilgang til, kan sende inn liste av scope separert med whitespace |


## License

[MIT](LICENSE)

