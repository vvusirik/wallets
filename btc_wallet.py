#! /usr/bin/python3
import secrets
import codecs
import ecdsa
import hashlib
import base58 as b58


### Helper functions
def sha256(m: bytes) -> bytes:
    return hashlib.sha256(m).digest()


def ripemd(m):
    ripemd = hashlib.new("ripemd160")
    ripemd.update(m)
    return ripemd.digest()


def to_hex(b: bytes) -> bytes:
    return codecs.encode(b, "hex")


def from_hex(h: bytes) -> bytes:
    return codecs.decode(h, "hex")

###

def generate_private_key() -> bytes:
    """Generates a random 256 bit (32 bytes) vector in the form of a hex string"""
    return secrets.token_bytes(32)


def wallet_import_format_private_key(private_key: bytes) -> bytes:
    """
    Converts private key byte array into "Wallet Import Format"
    Follows the steps in:
    https://en.bitcoin.it/wiki/Wallet_import_format
    """
    assert len(private_key) == 32

    # 1. Add 0x80 as version byte for mainnet
    versioned_private_key = b"\x80" + private_key

    # 2. Double SHA256 hash private key
    hash_version_private_key = sha256(sha256(versioned_private_key))

    # 3. Use first 4 bytes of hashed key as checksum
    checksum = hash_version_private_key[:4]

    # 4. Append the checksum to the versioned private key
    versioned_private_key_with_checksum = versioned_private_key + checksum

    # 5. Base58 encode the result
    encoded_private_key = b58.b58encode(versioned_private_key_with_checksum)
    return encoded_private_key


def generate_public_key(private_key: bytes) -> bytes:
    """Generate a public key from the private key input based on ECDSA with curve SECP256k1."""

    # Input must be 32 bytes (256 bits)
    assert len(private_key) == 32

    # Run ECDSA on the private key bytes to generate the public key
    public_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).verifying_key.to_string("compressed")
    return public_key


def generate_address(public_key: bytes) -> bytes:
    """
    Translate the ECDSA generated public key into a BTC address.
    Follows the steps in:
    https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
    """
    # Input must be 33 bytes
    assert len(public_key) == 33

    # 1. SHA256 hash
    public_key_sha_hash = sha256(public_key)

    # 2. RIPEMD-160 hash
    public_key_ripemd_sha_hash = ripemd(public_key_sha_hash)

    # 3. Append network version byte (x00 for mainnet)
    versioned_public_key_hash = b"\x00" + public_key_ripemd_sha_hash

    # 4. Double SHA256 previous result
    res = sha256(sha256(versioned_public_key_hash))

    # 5. First 4 bytes are used as a checksum
    checksum = res[:4]

    # 6. Concat versioned public key SHA + RIPEMD hash (3) with checksum (6)
    final_byte_address = versioned_public_key_hash + checksum

    # 7. Base58 encode for final address format
    encoded_address = b58.b58encode(final_byte_address)
    return encoded_address


if __name__ == "__main__":
    test_private_key = codecs.decode(b"18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725", "hex")

    wif_test_private_key = wallet_import_format_private_key(test_private_key)
    assert wif_test_private_key == b"5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V"

    public_key = generate_public_key(test_private_key)
    assert to_hex(public_key) == b"0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"

    address = generate_address(public_key)
    assert address == b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
