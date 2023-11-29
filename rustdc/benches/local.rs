use std::{net::SocketAddr, time::Instant};

use datacapsule::client::{
    manager::ManagerConnection,
    reader::{ReaderConnection, ReaderOperation},
    writer::{WriterConnection, WriterOperation, WriterResponse},
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Private, Public},
};
use tokio::{fs::File, io::AsyncReadExt};

async fn keys(pk_file: &str) -> (EcKey<Private>, EcKey<Public>, EcKey<Public>) {
    let group = &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let client_key = EcKey::generate(&group).unwrap();
    let client_pubkey = EcKey::from_public_key(&group, client_key.public_key()).unwrap();
    let mut pk_file = File::open(pk_file).await.unwrap();
    let mut pk = Vec::new();
    pk_file.read_to_end(&mut pk).await.unwrap();
    let server_key = EcKey::<Private>::private_key_from_pem(&pk).unwrap();
    let server_pubkey = EcKey::from_public_key(&group, server_key.public_key()).unwrap();
    (client_key, client_pubkey, server_pubkey)
}

const TOTAL_RECORDS: usize = 100000;
const RECORDS_PER_COMMIT: usize = 1000;

#[tokio::main]
async fn main() {
    let tt = Instant::now();

    let server_addr = "127.0.0.1:6142".parse::<SocketAddr>().unwrap();

    let (ck, cpubk, spubk) = keys("env/server_private.pem").await;

    println!(
        "know keys: {:?} {:?}",
        cpubk.public_key_to_der().unwrap().len(),
        spubk.public_key_to_der().unwrap().len()
    );

    let dc = {
        let mut mc = ManagerConnection::new(server_addr).await.unwrap();
        mc.create(&cpubk, &ck, &cpubk, &spubk, "cheese".into())
            .await
            .unwrap()
    };

    let mut wc = WriterConnection::new(
        dc,
        server_addr,
        spubk,
        cpubk.clone(),
        ck,
        *b"1234567812345678",
        [0; 32],
    )
    .await
    .unwrap();
    let mut rc = ReaderConnection::new(dc, server_addr, *b"1234567812345678", cpubk)
        .await
        .unwrap();

    let mut rawdata = Vec::<u8>::new();
    let mut write_ops = Vec::new();
    let mut write_reps = Vec::new();

    for a in 0..(TOTAL_RECORDS / RECORDS_PER_COMMIT) {
        for b in 0..RECORDS_PER_COMMIT {
            rawdata.extend_from_slice(b"data:");
            rawdata.extend_from_slice(&a.to_le_bytes());
            rawdata.extend_from_slice(&b.to_le_bytes());
        }
    }
    let mut i = 0;
    for _ in 0..(TOTAL_RECORDS / RECORDS_PER_COMMIT) {
        for _ in 0..RECORDS_PER_COMMIT {
            write_ops.push(WriterOperation::Write(&rawdata[21 * i..21 * (i + 1)]));
            i += 1;
        }
        write_ops.push(WriterOperation::Commit)
    }

    println!("Did setup in {:?}. DC: {:x?}", tt.elapsed(), dc);
    let tt = Instant::now();

    wc.do_operations(&write_ops, &mut write_reps).await.unwrap();

    println!("Did writes in {:?}. got {}", tt.elapsed(), write_reps.len());
    let tt = Instant::now();

    let mut ops = Vec::new();
    for r in &write_reps {
        if let WriterResponse::Write(h) = r {
            ops.push(ReaderOperation::Read(*h));
        }
    }
    let mut read_reps = Vec::new();
    rc.do_operations(&ops, &mut read_reps).await.unwrap();

    println!("Did reads in {:?}. got {:?}", tt.elapsed(), read_reps.len());
    let tt = Instant::now();

    let mut ops = Vec::new();
    for r in write_reps.iter().rev() {
        if let WriterResponse::Write(h) = r {
            ops.push(ReaderOperation::Prove(*h));
        }
    }
    let mut prove_reps = Vec::new();
    rc.do_operations(&ops, &mut prove_reps).await.unwrap();

    println!(
        "Did proofs in {:?}. got {:?}",
        tt.elapsed(),
        prove_reps.len()
    );
}
