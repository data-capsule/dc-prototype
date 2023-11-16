


// AES-128 encryption key
pub type SymmetricKey = [u8; 16];


// ECDSA signatures
// NIST P-256 (secp256r1) elliptic curve
pub type PublicKey = [u8; 64];
pub type PrivateKey = [u8; 256];
pub type Signature = [u8; 256];

// SHA-256 hash
pub type Hash = [u8; 32];
pub const NULL_HASH: Hash = [0; 32];

// convenient
pub struct SignedHash {
    signature: Signature,
    hash: Hash
}



fn create_hash(data: &[u8]) -> Hash {
    [0; 32]
}

fn encrypt(data: &[u8], key: SymmetricKey) -> Vec<u8> {
    vec![]
}

fn decrypt(data: &[u8], key: SymmetricKey) -> Vec<u8> {
    vec![]
}

fn sign(hash: Hash, key: PublicKey) -> Signature {
    [0; 256]
}

fn verify_signature(signature: Signature, hash: Hash) -> bool {
    true
}
