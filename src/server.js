const express = require('express')
const fs = require('fs').promises
const http = require('http')
const https = require('https')
const jwt = require('jsonwebtoken')
const _ = require('lodash/fp')

let config = undefined
let crypto = undefined
let ekvdb = undefined

function errToObj(err) {
  return _.merge({message: err.message, stack: err.stack.split('\n')}, err)
}

function httpRequest(options, lib = https) {
  return new Promise((resolve) => {
    lib.request(options, (res) => { resolve(res) }).end()
  })
}

function slurpStream(s) {
  return new Promise((resolve) => {
    const chunks = []
    s.on('data', (chunk) => { chunks.push(chunk) })
    s.on('end', () => { resolve(chunks) })
  })
}

function maybeParseJson(s) {
  try {
    return JSON.parse(s)
  } catch (e) {
    return s
  }
}

const app = express()

app.use((req, res, next) => {
  res.sendJson = (x) => {
    res.type('application/json')
    x = x instanceof Error ? errToObj(x) : x
    return res.send(JSON.stringify(x, null, 2) + '\n').end()
  }
  next()
})

async function fetchAccessToken() {
  try {
    return (await fs.readFile('.access-token', {encoding: 'utf8'})).trim()
  } catch (e) {
    const mRes = await httpRequest({
      hostname: 'metadata',
      path: '/computeMetadata/v1/instance/service-accounts/default/token',
      headers: {'Metadata-Flavor': 'Google'}
    }, http)
    return maybeParseJson((await slurpStream(mRes)).join('')).access_token
  }
}

async function getGcsObjectData(authorization, gsUrlString) {
  const url = new URL(gsUrlString)
  const gcsRes = await httpRequest({
    hostname: 'www.googleapis.com',
    path: '/download/storage/v1/b/'+
      encodeURIComponent(url.hostname)+'/o/'+encodeURIComponent(url.pathname.slice(1))+
      '?alt=media',
    headers: {authorization}
  })
  if (gcsRes.statusCode !== 200) {
    console.log(authorization)
    throw new Error(`failed to fetch ${url}: ${gcsRes.statusCode}`)
  }
  return (await slurpStream(gcsRes)).join('')
}

async function withConfig(req, res, next) {
  if (!config) {
    const authorization = `Bearer ${await fetchAccessToken()}`
    config = JSON.parse(await getGcsObjectData(authorization, process.env.CONFIG_GCS_URL))
    const authKey = await (async () => {
      try {
        return (await fs.readFile('.authkey', {encoding: 'utf8'})).trim()
      } catch (e) {
        return undefined
      }
    })()
    config = {...config, authKey}
  }
  if (!crypto) {
    crypto = require('./crypto')(Buffer.from(config.encryptionKeyBase64, 'base64'))
  }
  if (!ekvdb) {
    ekvdb = require('./encryptedkvdb')(crypto, {password: config.dbPassword})
  }
  next()
}

async function withAuth(req, res, next) {
  res.sendAuthError = () => {
    return res.status(401).sendJson(req.auth)
  }
  const authHeader = (req.headers['authorization'] || '').trim()
  if (authHeader.length === 0) {
    req.auth = {error: {message: 'missing Authorization header'}}
    return next()
  }
  const [type, value] = authHeader.split(/\s+/)
  if (type.toLowerCase() === 'key') {
    if (!config.authKey) {
      req.auth = {error: {
        message: 'key authorization disabled', type, value, header: authHeader}}
      return next()
    }
    if (value !== config.authKey) {
      req.auth = {error: {message: 'invalid auth key', type, value, header: authHeader}}
      return next()
    } else {
      req.auth = {key: value}
      return next()
    }
  } else if (type.toLowerCase() === 'bearer') {
    const gtRes = await httpRequest({
      hostname: 'oauth2.googleapis.com',
      path: '/tokeninfo?access_token='+value,
    })
    const gtResBody = maybeParseJson((await slurpStream(gtRes)).join(''))
    if (gtRes.statusCode !== 200) {
      req.auth = {error: {
        message: 'invalid bearer token', value, header: authHeader, cause: gtResBody}}
      return next()
    } else {
      req.auth = {google: gtResBody}
      return next()
    }
  } else {
    req.auth = {error: {message: 'invalid auth type', type, value, header: authHeader}}
    return next()
  }
}

app.get('/', (req, res) => {
  // req.log('got /')
  res.send(`The time is: ${(new Date()).toISOString()}\n`)
})

app.post('/.src', withAuth)

function jsToUnixTime(msSinceEpoch) { return msSinceEpoch / 1000 }
function unixToJsTime(sSinceEpoch) { return sSinceEpoch * 1000 }

app.get('/me', withConfig, withAuth, async (req, res) => {
  if (!req.auth.google) return res.sendAuthError();
  const pairs = await ekvdb.getPairs(req.auth.google.sub)
  res.sendJson(ekvdb.toPlain(pairs))
})

app.post('/shibboleth-token', withAuth, async (req, res) => {
  if (!req.auth.google) return res.sendAuthError();

  const shibToken = (await slurpStream(req)).join('')
  let payload = null
  try {
    const [headerJson, payloadJson, signatureBytes] =
      _.map((x) => Buffer.from(x, 'base64').toString())(shibToken.split('.'))
    payload = JSON.parse(payloadJson)
  } catch (e) {
    res.status(400)
      .sendJson({error: {message: 'failed to parse Shibboleth token', received: shibToken}})
  }

  const keyReq = await httpRequest({
    hostname: 'broad-shibboleth-prod.appspot.com',
    path: '/public-key.pem',
  })
  if (keyReq.statusCode !== 200) {
    return res.status(502).sendJson({error: {message: 'failed to fetch key for JWT verification'}})
  }
  const publicKeyPem = (await slurpStream(keyReq)).join('')
  try {
    jwt.verify(shibToken, publicKeyPem, {algorithms: ['RS256']})
  } catch (e) {
    return res.status(400).sendJson({error: {message: 'failed to verify JWT', cause: errToObj(e)}})
  }

  const pairs = await ekvdb.getPairs(req.auth.google.sub)
  await ekvdb.setValue(req.auth.google.sub, pairs,
    'linkedNihUsername', payload['eraCommonsUsername'])
  const thirtyDaysInSeconds = 60 * 60 * 24 * 30
  const exp = payload['iat'] + thirtyDaysInSeconds
  await ekvdb.setValue(req.auth.google.sub, pairs,
    'linkExpireTime', exp.toString())
  const values = _.pick(['linkedNihUsername', 'lastLinkTime', 'linkExpireTime']
    )(ekvdb.toPlain(await ekvdb.getPairs(req.auth.google.sub)))
  values.lastLinkTime = parseInt(values.lastLinkTime)
  values.lastLinkTimeHuman = (new Date(unixToJsTime(values.lastLinkTime))).toString()
  values.linkExpireTime = parseInt(values.linkExpireTime)
  values.linkExpireTimeHuman = (new Date(unixToJsTime(values.linkExpireTime))).toString()
  res.sendJson(values)
})

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).sendJson(err)
})

module.exports = app
