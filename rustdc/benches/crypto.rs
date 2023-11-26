use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::{hash::{Hasher, MessageDigest}, rand::rand_bytes, symm::{Crypter, Mode, Cipher}, ecdsa::EcdsaSig, ec::{EcKey, EcGroup}, pkey::Private, nid::Nid};




type Hash = [u8; 32];
type SymmetricKey = [u8; 16];

fn hash(b: &[u8]) -> Hash {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("hash");
    hasher.update(b).expect("hash");
    let res = hasher.finish().expect("hash");
    let bytes: &[u8] = &res;
    bytes.try_into().unwrap()
}

fn encrypt(seqno: u64, data: &[u8], key: &SymmetricKey) -> Vec<u8> {
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


fn decrypt(data: &[u8], key: &SymmetricKey) -> (u64, Vec<u8>) {
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

pub fn sign(hash: &Hash, key: &EcKey<Private>) -> Vec<u8> {
    let sig = EcdsaSig::sign(hash, key).expect("sign");
    sig.to_der().expect("sign")
}

pub fn verify_signature(sig: &[u8], hash: &Hash, key: &EcKey<Private>) -> bool {
    let sig = EcdsaSig::from_der(sig).expect("verify");
    sig.verify(hash, key).expect("verify")
}



pub fn criterion_benchmark(c: &mut Criterion) {
    let small = b"12345678123456781234567812345678".repeat(4); // 128 B
    let large = b"3141592653589793".repeat(1000); // 16 kB
    let key = b"abcdefghijklmnop";

    c.bench_function("small hash", |b| b.iter(|| hash(black_box(&small))));
    c.bench_function("large hash", |b| b.iter(|| hash(black_box(&large))));

    c.bench_function("small encrypt", |b| b.iter(|| encrypt(black_box(123), black_box(&small), black_box(key))));
    c.bench_function("large encrypt", |b| b.iter(|| encrypt(black_box(123), black_box(&large), black_box(key))));

    let encrypted_small = encrypt(123, &small, key);
    let encrypted_large = encrypt(123, &large, key);

    c.bench_function("small decrypt", |b| b.iter(|| decrypt(black_box(&encrypted_small), black_box(&key))));
    c.bench_function("large decrypt", |b| b.iter(|| decrypt(black_box(&encrypted_large), black_box(&key))));

    let hash = b"oerivjeorijergiojerogijergiocodp";
    let key = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
    let sig = sign(hash, &key);

    c.bench_function("sign", |b| b.iter(|| sign(black_box(hash), black_box(&key))));
    c.bench_function("verify", |b| b.iter(|| verify_signature(black_box(&sig), black_box(hash), black_box(&key))));

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
