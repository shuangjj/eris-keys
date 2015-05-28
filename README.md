# eris-keys

A simple tool for generating keys, producing and verifying signatures.

Features:
- basic support for ECDSA (secp256k1) and Shnorr (ed25519)
- command-line and http interfaces
- password based encryption (AES-GCM)

## WARNING: This is semi-audited cryptographic software. It should not yet be presumed safe. 

The code is mostly a fork of go-ethereum/crypto. Major changes include removing unecessary code (like supporting other ECDSA curves),
adding support for ED25519, and using AES-GCM for encryption.

# CLI

```
> eris-keys gen
552a3521a8a1021db265cf51866f7d1d07871950

> eris-keys pub 552a3521a8a1021db265cf51866f7d1d07871950
35a26ab63e3be6074fd28cf5ee739151c92f2ef05f0a1a3bf5ae13de3007fc9f

> eris-keys sign 41b27cb63e3be6074fd28cf5ee739151c92f2ef05f0a1a3cf5ae13de3007fc8e 552a3521a8a1021db265cf51866f7d1d07871950
dc74452ef6a565a32c97fd8fe47a64fbad2ce6269a70738ad6cd41c60662a33dd16c328211097282e407f9d693e437fedf5d34270ee793e8cacee594f6373800

> eris-keys verify 552a3521a8a1021db265cf51866f7d1d07871950 41b27cb63e3be6074fd28cf5ee739151c92f2ef05f0a1a3cf5ae13de3007fc8e dc74452ef6a565a32c97fd8fe47a64fbad2ce6269a70738ad6cd41c60662a33dd16c328211097282e407f9d693e437fedf5d34270ee793e8cacee594f6373800
true
```

Just run `eris-keys` or `eris-keys <cmd> --help` for more.

# HTTP

Start the daemon with `eris-keys --host localhost --port 12345 daemon`

There are four end points:

1) `/gen` 
	- Args: `type`
	- Return:  newly generated address

2) `/pub`
	- Args: `addr`
	- Return: the addresses' pubkey

3) `/sign`
	- Args: `addr`, `hash`
	- Return: the signature

4) `/verify`
	- Args: `addr`, `hash`, `sig`
	- Return: true or false


All arguments are passed as keyed values in the HTTP header. The response is a struct with two strings: a return value and an error.

All arguments and return values that would be byte arrays are presumend hex encoded

All methods accept optional `dir` and `auth` keys, which change the base directory the keys are written to/retrieved from, and allows for password based 
encryption of keys, respectively.




