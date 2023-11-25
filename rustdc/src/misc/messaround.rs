use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{DigestBytes, Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use std::time::Instant;

fn main() -> Result<(), ErrorStack> {
    println!("asd");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?; // NIST P-256 curve
    let key = EcKey::generate(&group)?;

    let mut ctx = BigNumContext::new()?;

    let public_key =
        &key.public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;

    let private_key = &key.private_key().to_vec();

    let pub_key_recon = EcKey::<Public>::public_key_from_der(public_key)?;
    let c1 = BigNum::from_slice(&private_key)?;
    // let priv_key_recon = EcKey::<Private>::from_private_components(&group, &(), 3)?;

    let private_key = key.private_key().to_vec();

    println!("{:x?}", key);
    println!("{:x?}", public_key);
    println!("{:x?}", private_key);

    {
        let now = Instant::now();

        let sig = EcdsaSig::sign(b"I like cheese and bread and butter", &key)?;

        let elapsed = now.elapsed();
        println!("Elapsed: {:?}", elapsed);

        let dd = sig.to_der()?;
        let cc = EcdsaSig::from_der(&dd)?;
        println!("der: {:?}", dd);
        println!("der: {:?}", dd.len());
        println!("cc: {:?}", cc.to_der()?);

        let now = Instant::now();

        let _cheese = sig.verify(b"I like cheese and bread and butter", &key)?;

        let elapsed = now.elapsed();
        println!("Elapsed: {:?}", elapsed);

        println!("{:?}", sig.to_der()?.len());
    }

    let mut long = Vec::<u8>::new();
    for a in 0..10000 {
        let x = ((a + 123) * (a + 22)) >> 3;
        long.push(x as u8);
    }

    let m1: &[u8] = &timed_hash(&long)?;
    let m2: &[u8] = &timed_hash(b"123456781234567812345678123456781234567812")?;
    let m3: &[u8] = &timed_hash2(m1, m2)?;
    let _m4: &[u8] = &timed_hash2(m2, m3)?;

    println!("{:x?}", m3);

    Ok(())
}

fn timed_hash(s: &[u8]) -> Result<DigestBytes, ErrorStack> {
    let now = Instant::now();

    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(s)?;
    let res = hasher.finish();

    println!("Elapsed: {:?}", now.elapsed());

    res
}

fn timed_hash2(s1: &[u8], s2: &[u8]) -> Result<DigestBytes, ErrorStack> {
    let now = Instant::now();

    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(s1)?;
    hasher.update(s2)?;
    let res = hasher.finish();

    println!("Elapsed: {:?}", now.elapsed());

    res
}
