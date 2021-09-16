# secp256k1-keys

## API

### `const keys = new KeyPair([sk])`

Instantiate a new key pair. If `sk` is not provided a random key shall be generated.

### `const sk = keys.secretKey`

Secret key.

### `const pk = keys.publicKey`

Public key in 33 byte compressed format.

### `const secret = keys.dh(pk)`

Perform Diffie-Hellman with another public key.

### `const sig = sign(data, recoverable = false)`

Sign some data.

### `KeyPair.verify(data, signature, [pk])`

Static method to verify signatures. If `pk` is not provided then the public key is assumed recoverable and the method shall return the recovered public key.
