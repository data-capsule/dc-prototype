use openssl::hash::{MessageDigest, Hasher};
use serde::{Serialize, Deserialize};

use crate::config::FANOUT;




// AES-128 encryption key
pub type SymmetricKey = [u8; 16];


// ECDSA signatures
// NIST P-256 (secp256r1) elliptic curve
pub type PublicKey = [u8; 32]; // TODO: ??
pub type PrivateKey = [u8; 32]; // TODO: ??

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signature([u64; 8]); // TODO: ??

// SHA-256 hash
pub type Hash = [u8; 32];
pub const NULL_HASH: Hash = [0; 32];

// convenient
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedHash {
    signature: Signature,
    pub hash: Hash
}


/*
TODO: this method is ugly
*/
pub fn hash_data(seqno: u64, encrypted_data: &[u8]) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    hasher.update(&seqno.to_le_bytes()).expect("hash");
    hasher.update(encrypted_data).expect("hash");
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

/*
TODO: this method is ugly
*/
pub fn hash_block(block: &[Hash; FANOUT]) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    for b in block {
        hasher.update(b).expect("hash");
    }
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

pub fn encrypt(data: &[u8], key: &SymmetricKey) -> Vec<u8> {
    todo!()
}

pub fn decrypt(data: &[u8], key: &SymmetricKey) -> Vec<u8> {
    todo!()
}

pub fn sign(hash: &Hash, key: &PrivateKey) -> SignedHash {
    todo!()
}

pub fn verify_signature(signed_hash: &SignedHash, key: &PublicKey) -> bool {
    todo!()
}
