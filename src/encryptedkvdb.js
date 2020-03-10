const _ = require('lodash/fp')
const mysql = require('mysql')

module.exports = function(crypto, dbOpts) {

  let cachedPool = undefined
  const qnTable = '`KEY_VALUE_PAIR`'
  const qnUserId = '`USER_ID`'
  const qnKey = '`KEY`'
  const qnIv = '`IV`'
  const qnValue = '`VALUE`'

  async function getPool() {
    if (!cachedPool) {
      cachedPool = await mysql.createPool({
        user: 'shib-profile',
        database: 'thurloe',
        socketPath: `/cloudsql/${dbOpts.instanceConnectionName}`,
        ...dbOpts
      })
    }
    return cachedPool
  }

  function query(sql, params) {
    return new Promise(async (resolve) => {
      (await getPool()).query(sql, params, (err, results, fields) => {
        resolve([err, results, fields])
      })
    })
  }

  async function getPairs(userId) {
    const [err, results, fields] = await query(
      `select * from ${qnTable} where ${qnUserId}=?`, [userId])
    if (err) { throw err }
    return _.reduce((r, v) => {
      return {
        ...r,
        [v.KEY]: {
          ivBase64: v.IV,
          cipheredValueBase64: v.VALUE,
          value: crypto.decipherValueFromBase64(v.IV, v.VALUE)
        }
      }
    })({})(results)
  }

  function toPlain(pairs) {
    return _.reduce((r, k) => {
      return {...r, [k]: pairs[k].value}
    })({})(_.keys(pairs))
  }

  async function setValue(userId, pairs, key, value) {
    const storedIvBase64 = _.get([key, 'ivBase64'])(pairs)
    const ivBase64 = storedIvBase64 || crypto.generateIvBase64()
    if (storedIvBase64) {
      const [err, results, fields] = await query(
        `update ${qnTable} set ${qnValue}=? where ${qnUserId}=? and ${qnKey}=?`,
        [crypto.cipherValueToBase64(ivBase64, value), userId, key]
      )
      if (err) { throw err }
      if (results.affectedRows !== 1) {
        throw new Error(`Error updating value for ${userId}[userId]:${key}[key].`+
          ` Affected row count was ${results.affectedRows}.`)
      }
    } else {
      const [err, results, fields] = await query(
        `insert into ${qnTable} (${qnUserId}, ${qnKey}, ${qnIv}, ${qnValue})` +
        ` values (?, ?, ?, ?)`,
        [userId, key, ivBase64, crypto.cipherValueToBase64(ivBase64, value)]
      )
      if (err) { throw err }
      if (results.affectedRows !== 1) {
        throw new Error(`Error inserting value for ${userId}[userId]:${key}[key].`+
          ` Affected row count was ${results.affectedRows}.`)
      }
    }
  }

  function decipherKvPairs(queryResult) {
    return _.reduce((r, v) => {
      return {
        ivs: {...r.ivs, [v.KEY]: v.IV},
        values: {...r.values, [v.KEY]: crypto.decipherValueFromBase64(v.IV, v.VALUE)}
      }
    })({ivs: {}, values: {}})(queryResult)
  }

  return {getPairs, setValue, toPlain}
}
