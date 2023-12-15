use std::{time::Instant, iter::zip};

use datacapsule::{client::{run_client, p2pclient::ClientConnection}, shared::dc_repr};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Private, Public},
};
use tokio::{fs::File, io::AsyncReadExt};


type Hash = [u8; 32];

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

const NUM_CLIENTS: usize = 10;
const UNIQUE_DCS: bool = true;
const TOTAL_RECORDS: usize = 1000000 / NUM_CLIENTS;
const RECORDS_PER_COMMIT: usize = 1000;




async fn new_client(n: usize, ck: &EcKey<Private>, cpubk: &EcKey<Public>, spubk: &EcKey<Public>, dc_name: [u8; 32]) -> ClientConnection {
    let name = format!("c{n}");
    let mut cc = run_client(&name, ck.clone(), cpubk.clone(), *b"1234567812345678", "env/net_config.json").await.unwrap();
    let (init_req, init_s) = cc.init_request(&dc_name);
    cc.send(&[init_req], "server1", false).unwrap();
    let resp = cc.wait_for_responses(&[init_s], &spubk).await;
    println!("client {name} initialized: {resp:?}");
    cc
}

async fn client_do_writes(cc: &mut ClientConnection, spubk: &EcKey<Public>, dc_name: [u8; 32]) -> Vec<Hash> {
    let mut all_hashes_for_read = Vec::new();
    {
        let mut rawdata = Vec::<u8>::new();
        let mut requests = Vec::new();
        let mut syncs = Vec::new();

        // TODO: make this a deque with a max capacity? might be more realistic
        let mut prev_written_records = Vec::new();

        for a in 0..(TOTAL_RECORDS / RECORDS_PER_COMMIT) {
            for b in 0..RECORDS_PER_COMMIT {
                rawdata.extend_from_slice(b"data:");
                rawdata.extend_from_slice(&a.to_le_bytes());
                rawdata.extend_from_slice(&b.to_le_bytes());
            }
        }

        // println!("Did setup in {:?}. DC: {:x?}", tt.elapsed(), dc_name);
        let tt = Instant::now();

        let mut i = 0;
        for _ in 0..(TOTAL_RECORDS / RECORDS_PER_COMMIT) {
            for _ in 0..RECORDS_PER_COMMIT {
                let (a, b, c) = cc.write_request(
                    &rawdata[21 * i..21 * (i + 1)], 
                    Vec::from([dc_repr::RecordBackPtr{
                        ptr: *prev_written_records.last().unwrap_or(&dc_name),
                        offset: Some(1)
                    }])
                );
                requests.push(a);
                syncs.push(b);
                prev_written_records.push(c);
                all_hashes_for_read.push(c);
                i += 1;
            }
            let (a, b) = cc.sign_request(prev_written_records.last().unwrap_or(&dc_name));
            requests.push(a);
            syncs.push(b);
        }

        // println!("Created requests in {:?}", tt.elapsed());
        cc.send(&requests, "server1", false).unwrap();
        // println!("After send {:?}", tt.elapsed());
        let resp = cc.wait_for_responses(&syncs, &spubk).await;
        // println!("Total write time after receive {:?}, got {}", tt.elapsed(), resp.len());
    }
    all_hashes_for_read
}


async fn client_do_reads(cc: &mut ClientConnection, spubk: &EcKey<Public>, hashes: &[Hash]) {
    let tt = Instant::now();
    let mut requests = Vec::new();
    let mut syncs = Vec::new();

    for h in hashes {
        let (a, b) = cc.read_request(h);
        requests.push(a);
        syncs.push(b);
    }

    // println!("Created requests in {:?}", tt.elapsed());
    cc.send(&requests, "server1", false).unwrap();
    // println!("After send {:?}", tt.elapsed());
    let resp = cc.wait_for_responses(&syncs, &spubk).await;
    // println!("Total read time after receive {:?}, got {}", tt.elapsed(), resp.len());
}

async fn client_do_proofs(cc: &mut ClientConnection, spubk: &EcKey<Public>, hashes: &[Hash]) {
    let tt = Instant::now();
    let mut requests = Vec::new();
    let mut syncs = Vec::new();

    for h in hashes.iter().rev() {
        let (a, b) = cc.proof_request(h);
        requests.push(a);
        syncs.push(b);
    }

    // println!("Created requests in {:?}", tt.elapsed());
    cc.send(&requests, "server1", false).unwrap();
    // println!("After send {:?}", tt.elapsed());
    let resp = cc.wait_for_responses(&syncs, &spubk).await;
    // println!("Total proof time after receive {:?}, got {}", tt.elapsed(), resp.len());
}


#[tokio::main]
async fn main() {
    let tt = Instant::now();

    let (ck, cpubk, spubk) = keys("env/server_private.pem").await;

    println!(
        "know keys: {:?} {:?}",
        cpubk.public_key_to_der().unwrap().len(),
        spubk.public_key_to_der().unwrap().len()
    );

    let mut original_client = run_client("client1", ck.clone(), cpubk.clone(), *b"1234567812345678", "env/net_config.json").await.unwrap();

    let mut dc_names = Vec::new();
    if UNIQUE_DCS {
        let mut reqs = Vec::new();
        let mut syncs = Vec::new();
        for n in 0..NUM_CLIENTS {
            let (c, s, dc) = original_client.manage_create_request(&cpubk, &format!("benchmarkdc{n}"));
            reqs.push(c);
            syncs.push(s);
            dc_names.push(dc);
        }
        original_client.send(&reqs, "server1", false).unwrap();
        let resp = original_client.wait_for_responses(&syncs, &spubk).await;
        println!("{:?}", resp);
    } else {
        let (capsule_req, capsule_s, dc_name) = original_client.manage_create_request(&cpubk, "benchmark");
        original_client.send(&[capsule_req], "server1", false).unwrap();
        let resp = original_client.wait_for_responses(&[capsule_s], &spubk).await;
        println!("{:?}", resp);
        dc_names = vec![dc_name; NUM_CLIENTS];
    }
    

    let mut clients = Vec::with_capacity(NUM_CLIENTS);
    for n in 0..NUM_CLIENTS {
        clients.push(new_client(n, &ck, &cpubk, &spubk, dc_names[n]).await)
    }

    println!("finished setting up {} clients in {:?}", clients.len(), tt.elapsed());
    println!("TESTING RBASE WITH {} CLIENTS {} UNIQUE {} RECORDS {} PER COMMIT", NUM_CLIENTS, UNIQUE_DCS, TOTAL_RECORDS, RECORDS_PER_COMMIT);


    let tt = Instant::now();
    let mut ffs = Vec::with_capacity(NUM_CLIENTS);
    for (cc, dc) in zip(&mut clients, &dc_names) {
        ffs.push(client_do_writes(cc, &spubk, *dc));
    }
    let hashes_per_client = futures::future::join_all(ffs).await;

    println!("All client writes done! finished in {:?}", tt.elapsed());

    let tt = Instant::now();
    let mut ffs = Vec::with_capacity(NUM_CLIENTS);
    for (cc, hs) in zip(&mut clients, &hashes_per_client) {
        ffs.push(client_do_reads(cc, &spubk, hs));
    }
    futures::future::join_all(ffs).await;

    println!("All client reads done! finished in {:?}", tt.elapsed());

    let tt = Instant::now();
    let mut ffs = Vec::with_capacity(NUM_CLIENTS);
    for (cc, hs) in zip(&mut clients, &hashes_per_client) {
        ffs.push(client_do_proofs(cc, &spubk, hs));
    }
    futures::future::join_all(ffs).await;

    println!("All client proofs done! finished in {:?}", tt.elapsed());


}
