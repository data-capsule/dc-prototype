use std::time::Instant;

use datacapsule::{client::run_client, shared::dc_repr};
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

    let (ck, cpubk, spubk) = keys("env/server_private.pem").await;

    println!(
        "know keys: {:?} {:?}",
        cpubk.public_key_to_der().unwrap().len(),
        spubk.public_key_to_der().unwrap().len()
    );

    let mut cc = run_client("client1", ck, cpubk.clone(), *b"1234567812345678", "env/net_config.json").await.unwrap();

    let (capsule_req, capsule_s, dc_name) = cc.manage_create_request(&cpubk, "benchmark");
    let (init_req, init_s) = cc.init_request(&dc_name);
    cc.send(&[capsule_req, init_req], "server1", false).unwrap();
    let resp = cc.wait_for_responses(&[capsule_s, init_s], &spubk).await;
    println!("{:?}", resp);
    println!("TESTING WITH {} RECORDS {} PER COMMIT", TOTAL_RECORDS, RECORDS_PER_COMMIT);

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

        println!("Did setup in {:?}. DC: {:x?}", tt.elapsed(), dc_name);
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

        println!("Created requests in {:?}", tt.elapsed());
        cc.send(&requests, "server1", false).unwrap();
        println!("After send {:?}", tt.elapsed());
        let resp = cc.wait_for_responses(&syncs, &spubk).await;
        println!("Total write time after receive {:?}, got {}", tt.elapsed(), resp.len());
    }
    {
        let tt = Instant::now();
        let mut requests = Vec::new();
        let mut syncs = Vec::new();

        for h in &all_hashes_for_read {
            let (a, b) = cc.read_request(h);
            requests.push(a);
            syncs.push(b);
        }

        println!("Created requests in {:?}", tt.elapsed());
        cc.send(&requests, "server1", false).unwrap();
        println!("After send {:?}", tt.elapsed());
        let resp = cc.wait_for_responses(&syncs, &spubk).await;
        println!("Total read time after receive {:?}, got {}", tt.elapsed(), resp.len());
    }
    {
        let tt = Instant::now();
        let mut requests = Vec::new();
        let mut syncs = Vec::new();

        for h in all_hashes_for_read.iter().rev() {
            let (a, b) = cc.proof_request(h);
            requests.push(a);
            syncs.push(b);
        }

        println!("Created requests in {:?}", tt.elapsed());
        cc.send(&requests, "server1", false).unwrap();
        println!("After send {:?}", tt.elapsed());
        let resp = cc.wait_for_responses(&syncs, &spubk).await;
        println!("Total proof time after receive {:?}, got {}", tt.elapsed(), resp.len());
    }
}
