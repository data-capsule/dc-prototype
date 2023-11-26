use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{Private, Public},
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use serde::{Deserialize, Serialize};

use crate::shared::config::FANOUT;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataCapsule {
    pub creator_pub_key: Vec<u8>,
    pub writer_pub_key: Vec<u8>,
    pub description: String,
    pub signature: Signature,
}

pub fn serialize_pubkey(key: &PublicKey) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    key.public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap()
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
/// [8 bytes seqno, 16 bytes iv, n bytes encrypted data]
pub fn encrypt(seqno: u64, data: &[u8], key: &SymmetricKey) -> Vec<u8> {
    let block_size = Cipher::aes_128_cbc().block_size();
    // 8 for seqno, 16 for iv, dlen + bsize for data
    let mut result = vec![0; 8 + 16 + data.len() + block_size];
    result[0..8].copy_from_slice(&seqno.to_le_bytes());
    let iv = &mut result[8..(8 + 16)];
    rand_bytes(iv).unwrap();

    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, key, Some(iv)).unwrap();

    // Encrypt data
    let mut count = 8 + 16;
    count += encrypter.update(data, &mut result[count..]).unwrap();
    count += encrypter.finalize(&mut result[count..]).unwrap();
    result.truncate(count);
    result
}

/*
TODO: this method is ugly. make return result
*/
/// Returns the sequence number and original, unencrypted data
pub fn decrypt(data: &[u8], key: &SymmetricKey) -> (u64, Vec<u8>) {
    if data.len() < 8 + 16 {
        panic!("return an error later lol");
    }
    let seqno = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let iv = &data[8..(8 + 16)];

    // Create a cipher context for decryption.
    let mut decrypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, key, Some(iv)).unwrap();

    let ciphertext = &data[(8 + 16)..];
    let block_size = Cipher::aes_128_cbc().block_size();
    let mut plaintext = vec![0; ciphertext.len() + block_size];

    // Decrypt 2 chunks of ciphertexts successively.
    let mut count = decrypter.update(ciphertext, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    (seqno, plaintext)
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
