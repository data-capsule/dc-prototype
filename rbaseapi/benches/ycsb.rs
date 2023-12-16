use std::{time::Instant, iter::zip, collections::{HashMap, HashSet}};

use datacapsule::{client::{run_client, p2pclient::{ClientConnection, ClientSync, Request}}, shared::dc_repr};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{Private, Public},
};
use tokio::{fs::File, io::AsyncReadExt};


const WORKLOAD: &str = "d";
const SIGN: bool = false;

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

#[derive(Debug, Clone)]
enum YCSBOp {
    Set(u64, String),
    Get(u64)
}

fn file_name(thing: &str) -> String {
    format!("../YCSB_traces/tracea_{thing}_{WORKLOAD}.txt")
}

async fn load_trace(file: &str) -> Vec<YCSBOp> {
    let mut ops = Vec::new();
    let mut pk_file = File::open(file).await.unwrap();
    let mut buf = String::new();
    pk_file.read_to_string(&mut buf).await.unwrap();
    for line in buf.lines() {
        let op = if line.starts_with("GET") {
            let key = &line[4..20];
            YCSBOp::Get(key.parse().unwrap())
        } else {
            let key = &line[4..20];
            YCSBOp::Set(key.parse().unwrap(), line[21..].into())
        };
        ops.push(op);
    }
    ops
}

fn process_trace(cc: &mut ClientConnection, kv: &mut HashMap<u64, Hash>, trace: &[YCSBOp]) -> (Vec<Request>, Vec<ClientSync>) {
    if SIGN {
       process_trace_sign(cc, kv, trace)
    } else {
       process_trace_raw(cc, kv, trace)
    }
}

fn process_trace_raw(cc: &mut ClientConnection, kv: &mut HashMap<u64, Hash>, trace: &[YCSBOp]) -> (Vec<Request>, Vec<ClientSync>) {
    let mut reqs = Vec::new();
    let mut syncs = Vec::new();

    let mut last_hash = [0; 32];
    
    for op in trace {
        let (r, s) = match op {
            YCSBOp::Set(k, v) => {
                let ptrs = Vec::from([dc_repr::RecordBackPtr{
                    ptr: last_hash,
                    offset: Some(1)
                }]);
                let (r, s, h) = cc.write_request(&v.as_bytes(), ptrs);
                kv.insert(*k, h);
                last_hash = h;
                (r, s)
            },
            YCSBOp::Get(k) => {
                let h = kv.get(k).unwrap();
                cc.read_request(h)
            }
        };
        reqs.push(r);
        syncs.push(s);
    }

    (reqs, syncs)
}

fn process_trace_sign(cc: &mut ClientConnection, kv: &mut HashMap<u64, Hash>, trace: &[YCSBOp]) -> (Vec<Request>, Vec<ClientSync>) {
    let mut reqs = Vec::new();
    let mut syncs = Vec::new();
    let mut unsigned_set = HashSet::new();

    let mut last_hash = [0; 32];
    
    for op in trace {
        let (r, s) = match op {
            YCSBOp::Set(k, v) => {
                let ptrs = Vec::from([dc_repr::RecordBackPtr{
                    ptr: last_hash,
                    offset: Some(1)
                }]);
                let (r, s, h) = cc.write_request(&v.as_bytes(), ptrs);
                last_hash = h;
                kv.insert(*k, h);
                unsigned_set.insert(*k);
                (r, s)
            },
            YCSBOp::Get(k) => {
                let h = kv.get(k).unwrap();
                if unsigned_set.contains(k) {
                    let (r, s) = cc.sign_request(&last_hash);
                    reqs.push(r);
                    syncs.push(s);
                    unsigned_set.clear();
                }
                let (r, s) = cc.read_request(h);
                reqs.push(r);
                syncs.push(s);
                cc.proof_request(h)
            }
        };
        reqs.push(r);
        syncs.push(s);
    }
    let (r, s) = cc.sign_request(&last_hash);
    reqs.push(r);
    syncs.push(s);

    (reqs, syncs)
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

    let mut cc = run_client("client1", ck, cpubk.clone(), *b"1234567812345678", "env/net_config.json").await.unwrap();

    let (capsule_req, capsule_s, dc_name) = cc.manage_create_request(&cpubk, "benchmark");
    let (init_req, init_s) = cc.init_request(&dc_name);
    cc.send(&[capsule_req, init_req], "server1", false).unwrap();
    let resp = cc.wait_for_responses(&[capsule_s, init_s], &spubk).await;
    println!("finished in {:?}, {:?}", tt.elapsed(), resp);
    println!("RBASE YCSB WORKLOAD {WORKLOAD} WOOHOO");

    let mut kv = HashMap::new();

    let pptrace = load_trace(&file_name("load")).await;
    let realtrace = load_trace(&file_name("run")).await;
    let NUM_OPERATIONS = realtrace.len();
    let (ppreqs, ppsyncs) = process_trace(&mut cc, &mut kv, &pptrace);
    cc.send(&ppreqs, "server1", false).unwrap();
    let resps = cc.wait_for_responses(&ppsyncs, &spubk).await;

    println!("operations: {}", resps.len());

    let tt = Instant::now();
    let (ppreqs, ppsyncs) = process_trace(&mut cc, &mut kv, &realtrace);
    cc.send(&ppreqs, "server1", false).unwrap();
    let resps = cc.wait_for_responses(&ppsyncs, &spubk).await;

    let duration = tt.elapsed();
    println!("operations: {}", resps.len());
    println!("finished! {duration:?} {} {:?}", NUM_OPERATIONS, (NUM_OPERATIONS as f64) / duration.as_secs_f64());
}
