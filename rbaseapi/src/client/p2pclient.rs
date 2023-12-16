use std::iter::zip;

use fakep2p::{P2PMessageBody, P2PSender};
use postcard::{from_bytes, to_stdvec};
use quick_cache::sync::Cache;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::shared::config;
use crate::shared::crypto::{
    decrypt, encrypt, hash_data, hash_dc_metadata, hash_record_header, serialize_pubkey, sign,
    verify_signature, Hash, PrivateKey, PublicKey, SymmetricKey,
};
use crate::shared::dc_repr::{self, Metadata, Record, RecordBackPtr, RecordHeader};
use crate::shared::request::{ManageRequest, RWRequest, Response};

use super::DCClientError;

pub use crate::shared::request::Request;

pub struct ClientConnection {
    name: String,
    signing_key: PrivateKey,
    signing_pub_key: PublicKey,
    encryption_key: SymmetricKey,
    sender: P2PSender,
    receiver: mpsc::UnboundedReceiver<P2PMessageBody>,
    proven_hash_cache: Cache<Hash, ()>,
}

#[derive(Debug, Clone)]
pub enum ClientSync {
    ManageCreate(Hash),
    ManageRead(Hash),
    Init,
    Write,
    Sign(Hash),
    Read(Hash),
    Proof(Hash),
    SubscribeFresh,
}

#[derive(Debug, Clone)]
pub enum ClientResponse {
    ManageCreate,
    ManageRead(Metadata),
    Init,
    Write,
    Sign,
    Read(Vec<u8>, Vec<RecordBackPtr>),
    Proof(bool),
    SubscribeFresh(Vec<Hash>),
    CryptographyFail,
    ServerFail,
}

impl ClientConnection {
    pub fn new(
        name: &str,
        signing_key: PrivateKey,
        signing_pub_key: PublicKey,
        encryption_key: SymmetricKey,
        sender: P2PSender,
    ) -> (Self, UnboundedSender<P2PMessageBody>) {
        let (s, r) = mpsc::unbounded_channel();
        let c = ClientConnection {
            name: name.into(),
            signing_key,
            signing_pub_key,
            encryption_key,
            sender,
            receiver: r,
            proven_hash_cache: Cache::new(config::CACHE_SIZE),
        };
        (c, s)
    }

    pub fn manage_create_request(
        &self,
        writer_pub_key: &PublicKey,
        description: &str,
    ) -> (Request, ClientSync, Hash) {
        let creator_pub_key = serialize_pubkey(&self.signing_pub_key);
        let writer_pub_key = serialize_pubkey(writer_pub_key);
        let hash = hash_dc_metadata(&creator_pub_key, &writer_pub_key, description);
        let dc = Metadata {
            creator_pub_key,
            writer_pub_key,
            description: description.into(),
            signature: sign(&hash, &self.signing_key),
        };
        (
            Request::Manage(ManageRequest::Create(dc)),
            ClientSync::ManageCreate(hash),
            hash,
        )
    }

    pub fn manage_read_request(&self, dc: &Hash) -> (Request, ClientSync) {
        (
            Request::Manage(ManageRequest::Read(*dc)),
            ClientSync::ManageRead(*dc),
        )
    }

    pub fn init_request(&self, dc: &Hash) -> (Request, ClientSync) {
        (Request::Init(*dc), ClientSync::Init)
    }

    pub fn write_request(
        &self,
        data: &[u8],
        ptrs: Vec<RecordBackPtr>,
    ) -> (Request, ClientSync, Hash) {
        // TODO: @Ted review this
        let encrypted_data = encrypt(data, &self.encryption_key);
        let body_ptr = hash_data(&encrypted_data);
        let header = RecordHeader {
            body_ptr,
            record_backptrs: ptrs,
        };
        let record_name = hash_record_header(&header);
        (
            Request::RW(RWRequest::Write(Record {
                body: encrypted_data,
                header,
            })),
            ClientSync::Write,
            record_name,
        )
    }

    pub fn sign_request(&self, record: &Hash) -> (Request, ClientSync) {
        let signature = sign(record, &self.signing_key);
        (
            Request::RW(RWRequest::Sign(*record, signature)),
            ClientSync::Sign(*record),
        )
    }

    pub fn read_request(&self, record: &Hash) -> (Request, ClientSync) {
        (
            Request::RW(RWRequest::Read(*record)),
            ClientSync::Read(*record),
        )
    }

    pub fn proof_request(&self, record: &Hash) -> (Request, ClientSync) {
        (
            Request::RW(RWRequest::Proof(*record)),
            ClientSync::Proof(*record),
        )
    }

    pub fn freshness_request(&self) -> (Request, ClientSync) {
        todo!()
    }

    /// Sends all the requests to the given destination
    pub fn send(
        &mut self,
        requests: &[Request],
        dest: &str,
        multi: bool,
    ) -> Result<(), DCClientError> {
        let r = to_stdvec(requests).unwrap(); // TODO: handle well
        let r = P2PMessageBody {
            dest: dest.into(),
            sender: self.name.clone(),
            content: r,
            metadata: Vec::new(),
        };
        if multi {
            self.sender.send_multi(r)?
        } else {
            self.sender.send_one(r)?
        }
        Ok(())
    }

    /// A simple function for benchmarking. Waits for and verifies all results.
    /// A real client would probably want to do something more interesting, and
    /// also handle out-of-order messages and miscellaneous failures
    pub async fn wait_for_responses(
        &mut self,
        syncs: &[ClientSync],
        dc_server_key: &PublicKey,
    ) -> Vec<ClientResponse> {
        let mut responses = Vec::new();
        let m = self.receiver.recv().await.unwrap();
        let cheese: Vec<Response> = from_bytes(&m.content).unwrap(); // TODO: handle well
        assert!(cheese.len() == syncs.len()); // TODO: handle well
        for (resp, sync) in zip(cheese, syncs) {
            responses.push(self.response_to_client_response(dc_server_key, resp, sync));
        }
        responses
    }

    fn response_to_client_response(
        &mut self,
        dc_server_key: &PublicKey,
        resp: Response,
        sync: &ClientSync,
    ) -> ClientResponse {
        match (resp, sync) {
            (Response::ManageCreate(sig), ClientSync::ManageCreate(hash)) => {
                if verify_signature(&sig, hash, dc_server_key) {
                    ClientResponse::ManageCreate
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::ManageRead(dc), ClientSync::ManageRead(hash)) => {
                if &hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description)
                    == hash
                {
                    ClientResponse::ManageRead(dc)
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::Init, ClientSync::Init) => {
                self.proven_hash_cache = Cache::new(config::CACHE_SIZE);
                ClientResponse::Init
            }
            (Response::WriteData(_), ClientSync::Write) => ClientResponse::Write,
            (Response::WriteSign(sig), ClientSync::Sign(hash)) => {
                if verify_signature(&sig.1, hash, dc_server_key) {
                    ClientResponse::Sign
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::ReadRecord(record), ClientSync::Read(hash)) => {
                // TODO: @Ted review this
                let header_match = &hash_record_header(&record.header) == hash;
                let body_match = hash_data(&record.body) == record.header.body_ptr;
                if header_match && body_match {
                    let plaintext = decrypt(&record.body, &self.encryption_key);
                    ClientResponse::Read(plaintext, record.header.record_backptrs)
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::ReadProof(proof), ClientSync::Proof(hash)) => {
                let success = verify_proof(
                    hash,
                    &proof,
                    &self.signing_pub_key,
                    &mut self.proven_hash_cache,
                )
                .is_ok();
                ClientResponse::Proof(success)
            }
            (Response::SubscribeFresh(commits), ClientSync::SubscribeFresh) => {
                todo!()
            }
            _ => ClientResponse::ServerFail,
        }
    }
}

fn verify_proof(
    record_name_to_prove: &Hash,
    best_effort_proof: &dc_repr::BestEffortProof,
    writer_public_key: &PublicKey,
    proven_hash_cache: &Cache<Hash, ()>,
) -> Result<(), DCClientError> {
    if let Some((signed_record_name, signature)) = &best_effort_proof.signature {
        // if server returns a bad signature, assume rest of best-effort-proof doesn't help
        // (e.g. server is malicious) and end early
        if !verify_signature(&signature, &signed_record_name, writer_public_key) {
            return Err(DCClientError::BadProof(
                "bad proof for record_name ...".into(),
            ));
        }

        proven_hash_cache.insert(*signed_record_name, ());

        if *signed_record_name == *record_name_to_prove {
            return Ok(());
        }
    }

    let mut iter = best_effort_proof.chain.clone().into_iter();
    match iter.next() {
        None => Err(DCClientError::BadProof(
            "bad proof for record_name ...".into(),
        )),
        Some(first_in_chain) => {
            if hash_record_header(&first_in_chain) != *record_name_to_prove {
                return Err(DCClientError::BadProof(
                    "bad proof for record_name ...".into(),
                ));
            }

            let mut prev_record_header = first_in_chain;
            while let Some(curr_record_header) = iter.next() {
                let prev_record_name = hash_record_header(&prev_record_header);
                let curr_record_name = hash_record_header(&curr_record_header);
                if let Some(_) = proven_hash_cache.get(&curr_record_name) {
                    // found proof for curr_record_name (and every preceding record in chain, including the record to prove)
                    let mut proven_iter = best_effort_proof.chain.clone().into_iter();
                    while let Some(proven_record_header) = proven_iter.next() {
                        let proven_record_name = hash_record_header(&proven_record_header);
                        proven_hash_cache.insert(proven_record_name, ());
                        if proven_record_name == curr_record_name {
                            break;
                        }
                    }
                    return Ok(());
                }
                // if curr_record_header.prev_record_ptr == prev_record_name
                //     || curr_record_header
                //         .additional_record_ptrs
                if curr_record_header
                    .record_backptrs
                    .clone()
                    .into_iter()
                    .any(|p| p.ptr == prev_record_name)
                {
                    prev_record_header = curr_record_header;
                } else {
                    return Err(DCClientError::BadProof(
                        "bad proof for record_name ...".into(),
                    ));
                }
            }
            Err(DCClientError::BadProof(
                "bad proof for record_name ...".into(),
            ))
        }
    }
}
