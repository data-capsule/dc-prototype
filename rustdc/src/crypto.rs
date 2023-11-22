use serde::{Serialize, Deserialize};

use crate::config::FANOUT;




// AES-128 encryption key
pub type SymmetricKey = [u8; 16];


// ECDSA signatures
// NIST P-256 (secp256r1) elliptic curve
pub type PublicKey = [u8; 32]; // TODO: ??
pub type PrivateKey = [u8; 32]; // TODO: ??

#[derive(Serialize, Deserialize, Debug)]
pub struct Signature([u64; 8]); // TODO: ??

// SHA-256 hash
pub type Hash = [u8; 32];
pub const NULL_HASH: Hash = [0; 32];

// convenient
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedHash {
    signature: Signature,
    hash: Hash
}



pub fn hash_data(data: &[u8]) -> Hash {
    [0; 32]
}

pub fn hash_block(block: &[Hash; FANOUT]) -> Hash {
    [0; 32]
}

pub fn encrypt(data: &[u8], key: SymmetricKey) -> Vec<u8> {
    vec![]
}

pub fn decrypt(data: &[u8], key: SymmetricKey) -> Vec<u8> {
    vec![]
}

pub fn sign(hash: Hash, key: PublicKey) -> Signature {
    [0; 256]
}

pub fn verify_signature(signature: Signature, hash: Hash) -> bool {
    true
}
