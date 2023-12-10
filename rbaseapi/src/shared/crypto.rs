use openssl::{
    ec::EcKey,
    ecdsa::EcdsaSig,
    hash::{Hasher, MessageDigest},
    pkey::{Private, Public},
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};

use crate::shared::config::FANOUT;
use crate::shared::dc_repr;

// AES-128 encryption key
pub type SymmetricKey = [u8; 16];

// ECDSA signatures
// NIST P-256 (secp256r1) elliptic curve
// EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?)?
pub type PublicKey = EcKey<Public>;
pub type PrivateKey = EcKey<Private>;

// SHA-256 hash
pub type Hash = [u8; 32];
pub type HashNode = [Hash; FANOUT];
pub const NULL_HASH: Hash = [0; 32];

pub type Signature = Vec<u8>;

pub fn serialize_pubkey(key: &PublicKey) -> Vec<u8> {
    key.public_key_to_der().unwrap()
}

pub fn deserialize_pubkey(key: &[u8]) -> PublicKey {
    EcKey::<Public>::public_key_from_der(key).unwrap()
}

pub fn deserialize_private_key_from_pem(pem: &[u8]) -> PrivateKey {
    EcKey::<Private>::private_key_from_pem(pem).unwrap()
}

/*
TODO: this method is ugly. make return result
*/
pub fn hash_dc_metadata(c_pk: &[u8], w_pk: &[u8], desc: &str) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    hasher.update(c_pk).expect("hash");
    hasher.update(w_pk).expect("hash");
    hasher.update(desc.as_bytes()).expect("hash");
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

/*
TODO: this method is ugly. make return result
*/
pub fn hash_record_header(record_header: &dc_repr::RecordHeader) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    // hasher.update(&record_header.dc_name).expect("hash");
    hasher.update(&record_header.body_ptr).expect("hash");
    // hasher.update(&record_header.prev_record_ptr).expect("hash");
    for record_backptr in &record_header.record_backptrs {
        hasher.update(&record_backptr.ptr).expect("hash");
        // TODO: hash additional_record_ptr.offset
    }
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

/*
TODO: this method is ugly. make return result
*/
pub fn hash_data(encrypted_data: &[u8]) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    hasher.update(encrypted_data).expect("hash");
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

/*
TODO: this method is ugly. make return result
*/
pub fn hash_node(node: &HashNode) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    for h in node {
        hasher.update(h).expect("hash");
    }
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

/*
TODO: this method is ugly. make return result
*/
/// Returns a vector of bytes with the following format:
/// [16 bytes iv, n bytes encrypted data]
pub fn encrypt(data: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let block_size = Cipher::aes_128_cbc().block_size();
    // 16 for iv, dlen + bsize for data
    let mut result = vec![0; 16 + data.len() + block_size];
    let iv = &mut result[0..16];
    rand_bytes(iv).unwrap();

    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, key, Some(iv)).unwrap();

    // Encrypt data
    let mut count = 16;
    count += encrypter.update(data, &mut result[count..]).unwrap();
    count += encrypter.finalize(&mut result[count..]).unwrap();
    result.truncate(count);
    result
}

/*
TODO: this method is ugly. make return result
*/
/// Returns the original, unencrypted data
pub fn decrypt(data: &[u8], key: &SymmetricKey) -> Vec<u8> {
    if data.len() < 16 {
        panic!("return an error later lol");
    }
    let iv = &data[0..16];

    // Create a cipher context for decryption.
    let mut decrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, key, Some(iv)).unwrap();

    let ciphertext = &data[16..];
    let block_size = Cipher::aes_128_cbc().block_size();
    let mut plaintext = vec![0; ciphertext.len() + block_size];

    // Decrypt 2 chunks of ciphertexts successively.
    let mut count = decrypter.update(ciphertext, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

/*
TODO: this method is ugly. make return result
*/
pub fn sign(hash: &Hash, key: &PrivateKey) -> Signature {
    let sig = EcdsaSig::sign(hash, key).expect("sign");
    sig.to_der().expect("sign")
}

/*
TODO: this method is ugly. make return result
*/
/// Verifies the signature. If the signature is valid, returns the hash that was signed.
pub fn verify_signature(signature: &Signature, hash: &Hash, key: &PublicKey) -> bool {
    let sig = EcdsaSig::from_der(signature).expect("verify");
    sig.verify(hash, key).expect("verify")
}
