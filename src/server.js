const cors = require('cors')
const express = require('express')
const fs = require('fs').promises
const http = require('http')
const https = require('https')
const jwt = require('jsonwebtoken')
const _ = require('lodash/fp')
const u = require('utils')

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

app.use(cors())

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

const configGcsUrl = 'gs://broad-shibboleth-prod.appspot.com/secrets/secrets.20200310a.json'

async function withConfig(req, res, next) {
  if (res.locals.config) { return next() }
  const authorization = `Bearer ${await fetchAccessToken()}`
  res.locals.config = JSON.parse(await getGcsObjectData(authorization, configGcsUrl))
  next()
}

function withCrypto(envName) {
  return (req, res, next) => {
    if (!res.locals.config) { return next(new Error('Missing configuration')) }
    const {config} = res.locals
    const key = Buffer.from(config[envName].encryptionKeyBase64, 'base64')
    res.locals.crypto = require('./crypto')(key)
    next()
  }
}

function withEkvdb(envName) {
  const instanceConnectionName = envName === 'dev' ?
    'broad-dsde-dev:us-central1:thurloe-cloudsql-dev201-9e45a2fc870e72f2' :
    'broad-dsde-prod:us-central1:thurloe-cloudsql-prod201-905168db8ab5e528'
  return (req, res, next) => {
    const {config, crypto} = res.locals
    if (!config) { return next(new Error('Missing configuration')) }
    if (!crypto) { return next(new Error('Missing crypto library')) }
    const dbOpts = {instanceConnectionName, password: config[envName].dbPassword}
    res.locals.ekvdb = require('./encryptedkvdb')(crypto, dbOpts)
    next()
  }
}

class StructError extends Error {
  constructor(obj) {
    super(obj.message)
    _.forEach(k => {this[k] = obj[k]})(_.keys(obj))
  }
}

class ExternalRequestError extends Error {
  constructor(res) {
    super(`External request returned status: ${res.statusCode}`)
    this.res = res
  }
}

async function hasPermission(authorizationHeaderValue, permissionName) {
  const permsCheck = u.httpreq({
    hostname: 'cloudresourcemanager.googleapis.com',
    path: `/v1/projects/${process.env.GOOGLE_CLOUD_PROJECT}:testIamPermissions`,
    method: 'post',
    headers: {'Authorization': authorizationHeaderValue, 'Content-Type': 'application/json'}
  })
  permsCheck.req.write(JSON.stringify({permissions: [permissionName]}))
  permsCheck.req.end()
  await permsCheck.resp
  if (permsCheck.res.statusCode !== 200) { throw new ExternalRequestError(permsCheck.res) }
  permsCheck.body = await u.consumeStreamp(permsCheck.res)
  const grantedPerms = JSON.parse(permsCheck.body.toString()).permissions
  if (_.indexOf(permissionName)(grantedPerms) !== -1) {
    return [null, true]
  } else {
    return [{
      message: 'missing required permission',
      requiredPermission: requiredPerm,
      grantedPermissions: grantedPerms
    }, false]
  }
}

app.post('/.src', async (req, res, next) => {
  const [err, hasPerm] = await hasPermission(
    req.headers['authorization'],
    'appengine.applications.update'
  )
  if (hasPerm) {
    res.locals.isReloadOkay = true
    return next()
  } else {
    res.status(403).send(JSON.stringify(err, null, 2)).end()
  }
})

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
  if (type.toLowerCase() === 'bearer') {
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

function jsToUnixTime(msSinceEpoch) { return msSinceEpoch / 1000 }
function unixToJsTime(sSinceEpoch) { return sSinceEpoch * 1000 }

async function getMe(req, res) {
  if (!req.auth.google) return res.sendAuthError();
  const {ekvdb} = res.locals
  const pairs = await ekvdb.getPairs(req.auth.google.sub)
  res.sendJson(ekvdb.toPlain(pairs))
}

app.get('/dev/me', withConfig, withCrypto('dev'), withEkvdb('dev'), withAuth, getMe)
app.get('/me', withConfig, withCrypto('prod'), withEkvdb('prod'), withAuth, getMe)

async function getPublicKey(envName) {
  const path = envName === 'dev' ? '/dev/public-key.pem' : '/public-key.pem'
  const keyReq = await httpRequest({hostname: 'broad-shibboleth-prod.appspot.com', path})
  if (keyReq.statusCode !== 200) {
    throw new StructError({message: 'failed to fetch key for JWT verification', path})
  }
  return (await slurpStream(keyReq)).join('')
}

function parseJwtPayload(jwt) {
  try {
    const [headerJson, payloadJson, signatureBytes] =
      _.map((x) => Buffer.from(x, 'base64').toString())(jwt.split('.'))
    return JSON.parse(payloadJson)
  } catch (e) {
    throw new StructError({message: 'failed to parse token payload', jwt})
  }
}

function postShibbolethToken(envName) {
  return async (req, res) => {
    if (!req.auth.google) { return res.sendAuthError() }

    const {ekvdb} = res.locals
    const shibToken = (await slurpStream(req)).join('')
    const payload = parseJwtPayload(shibToken)
    const publicKeyPem = await getPublicKey(envName)

    try {
      jwt.verify(shibToken, publicKeyPem, {algorithms: ['RS256']})
    } catch (e) {
      return res.status(400).sendJson({error: {message: 'failed to verify JWT', cause: errToObj(e)}})
    }

    const sub = req.auth.google.sub
    const payloadUsername = payload['eraCommonsUsername']
    const pairs = await ekvdb.getPairs(sub)
    await ekvdb.setValue(sub, pairs, 'linkedNihUsername', payloadUsername)
    const thirtyDaysInSeconds = 60 * 60 * 24 * 30
    const exp = payload['iat'] + thirtyDaysInSeconds
    await ekvdb.setValue(sub, pairs, 'linkExpireTime', exp.toString())
    const values = _.pick(['linkedNihUsername', 'lastLinkTime', 'linkExpireTime']
      )(ekvdb.toPlain(await ekvdb.getPairs(sub)))
    values.lastLinkTime = parseInt(values.lastLinkTime)
    values.lastLinkTimeHuman = (new Date(unixToJsTime(values.lastLinkTime))).toString()
    values.linkExpireTime = parseInt(values.linkExpireTime)
    values.linkExpireTimeHuman = (new Date(unixToJsTime(values.linkExpireTime))).toString()
    res.sendJson(values)
  }
}

app.post('/dev/shibboleth-token',
  withConfig, withCrypto('dev'), withEkvdb('dev'), withAuth,
  postShibbolethToken('dev')
)
app.post('/shibboleth-token',
  withConfig, withCrypto('prod'), withEkvdb('prod'), withAuth,
  postShibbolethToken('prod')
)

// app.get('/repl', withConfig, withCrypto('dev'), withEkvdb('dev'), withAuth, async (req, res) => {
//   if (!req.auth.google) return res.sendAuthError();
//   const {ekvdb} = res.locals
//   const pairs = await ekvdb.getPairs(req.auth.google.sub)
//   res.sendJson(ekvdb.toPlain(pairs))
// })

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).sendJson(err)
})

module.exports = app
