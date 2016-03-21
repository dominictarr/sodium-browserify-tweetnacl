
var tweetnacl = require('tweetnacl/nacl-fast')
var Sha256 = require('sha.js/sha256')
var ed2curve = require('ed2curve')
var auth = require('tweetnacl-auth')

exports.crypto_hash_sha256 = function (msg) {
  return new Sha256().update(msg).digest()
}

exports.crypto_sign_seed_keypair = function (seed) {
  return tweetnacl.sign.keyPair.fromSeed(seed)
}

exports.crypto_sign_keypair = function () {
  return tweetnacl.sign.keyPair()
}

exports.crypto_sign_detached = function (msg, skey) {
  return tweetnacl.sign.detached(msg, skey)
}

exports.crypto_sign = tweetnacl.sign

exports.crypto_sign_open = tweetnacl.sign.open

exports.crypto_sign_verify_detached = function (sig, msg, pkey) {
  return tweetnacl.sign.detached.verify(msg, sig, pkey)
}

exports.crypto_box_keypair = function () {
  return tweetnacl.box.keyPair()
}


exports.crypto_hash = tweetnacl.hash

exports.crypto_secretbox_easy = tweetnacl.secretbox
exports.crypto_secretbox_open_easy = function (ctxt, nonce, key) {
  return tweetnacl.secretbox.open(ctxt, nonce, key) || null
}

exports.crypto_sign_ed25519_pk_to_curve25519 = ed2curve.convertPublicKey
exports.crypto_sign_ed25519_sk_to_curve25519 = ed2curve.convertSecretKey


exports.crypto_box_easy = tweetnacl.box
exports.crypto_box_open_easy = function (ctxt, nonce, pkey, skey) {
  return tweetnacl.box.open(ctxt, nonce, pkey, skey) || null
}

exports.crypto_scalarmult = tweetnacl.scalarMult

//exports.crypto_auth = tweetnacl.auth
//exports.crypto_auth_verify = tweetnacl.auth.verify

exports.crypto_auth = function (msg, key) {
  return new Buffer(auth(msg, key))
}

exports.crypto_auth_verify = function (mac, msg, key) {
  var _mac = exports.crypto_auth(msg, key)
  var d = true
  //constant time comparson
  for(var i = 0; i < auth.length; i++) {
    d = d && (_mac[i] === mac[i])
  }
  return +!d
}

