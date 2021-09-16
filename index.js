const crypto = require('crypto')
const secp = require('secp256k1-native')
const assert = require('nanoassert')

module.exports = class KeyPair {
  constructor (opts = {}) {
    this._ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)

    this.secretKey = opts.sk || randomScalar()
    this.publicKey = Buffer.alloc(33)

    this._pk = Buffer.alloc(secp.secp256k1_PUBKEYBYTES)

    secp.secp256k1_ec_pubkey_create(this._ctx, this._pk, this.secretKey)
    secp.secp256k1_ec_pubkey_serialize(this._ctx, this.publicKey, this._pk, secp.secp256k1_ec_COMPRESSED)
  }

  dh (pk) {
    assert(pk.byteLength === secp.secp256k1_PUBKEYBYTES)
    assert(secp.crypto_core_ristretto255_is_valid_point(pk), 'invalid ristretto key')

    const output = Buffer.alloc(secp.crypto_scalarmult_ristretto255_BYTES)

    secp.secp256k1_ecdh(
      pk,
      output,
      this._ctx,
      this.secretKey
    )

    return output
  }

  sign (data, recoverable = false) {
    const sigLength = recoverable
      ? secp.secp256k1_ecdsa_recoverable_SIGBYTES
      : secp.secp256k1_ecdsa_SIGBYTES

    const sig = Buffer.alloc(sigLength)
    const msg32 = sha256(data)

    if (recoverable) {
      secp.secp256k1_ecdsa_sign_recoverable(this._ctx, sig, msg32, this.secretKey)
    } else {
      secp.secp256k1_ecdsa_sign(this._ctx, sig, msg32, this.secretKey)
    }

    return sig
  }


  static verify (data, signature, pk) {
    const ctx = secp.secp256k1_context_create(secp.secp256k1_context_VERIFY)
    const recoverable = signature.byteLength > 64
    const msg32 = sha256(data)

    if (pk instanceof Uint8Array) {
      return secp.secp256k1_ecdsa_verify(ctx, signature, msg32, pk)
    }

    const pubkey = Buffer.alloc(secp.secp256k1_PUBKEYBYTES)
    secp.secp256k1_ecdsa_recover(ctx, pubkey, sig, msg32)

    return pubkey
  }
}

function randomScalar () {
  const ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)
  do {
    seckey = crypto.randomBytes(secp.secp256k1_SECKEYBYTES)
  } while (!secp.secp256k1_ec_seckey_verify(ctx, seckey))
  return seckey
}

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}
