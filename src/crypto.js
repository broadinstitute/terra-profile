const crypto = require('crypto')

module.exports = function(key) {

  const algorithm = 'aes-256-cbc'

  function createCipher(ivBase64) {
    return crypto.createCipheriv(algorithm, key, Buffer.from(ivBase64, 'base64'))
  }

  function cipherValueToBase64(ivBase64, value) {
    const iv = ivBase64 || crypto.randomBytes(16).toString('base64')
    const cipher = createCipher(ivBase64)
    let ciphered = cipher.update(value, 'utf8', 'base64')
    ciphered += cipher.final('base64')
    return ciphered
  }

  function createDecipher(ivBase64) {
    return crypto.createDecipheriv(algorithm, key, Buffer.from(ivBase64, 'base64'))
  }

  function decipherValueFromBase64(ivBase64, cipheredValueBase64) {
    const decipher = createDecipher(ivBase64)
    let deciphered = decipher.update(cipheredValueBase64, 'base64', 'utf8')
    deciphered += decipher.final('utf8')
    return deciphered
  }

  function generateIvBase64() {
    return crypto.randomBytes(16).toString('base64')
  }

  return {cipherValueToBase64, decipherValueFromBase64, generateIvBase64}
}
