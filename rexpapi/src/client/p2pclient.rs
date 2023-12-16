use std::iter::zip;

use fakep2p::{P2PMessageBody, P2PSender};
use postcard::{to_stdvec, from_bytes};
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::shared::crypto::{
    decrypt, encrypt, hash_data, hash_dc_metadata, hash_node, serialize_pubkey, sign,
    verify_signature, DataCapsule, Hash, HashNode, PrivateKey, PublicKey, Signature, SymmetricKey,
};
use crate::shared::merkle::merkle_tree_root;
use crate::shared::readstate::ReadState;
use crate::shared::request::Response;

use super::DCClientError;

pub use crate::shared::request::Request;

pub struct ClientConnection {
    name: String,
    signing_key: PrivateKey,
    signing_pub_key: PublicKey,
    encryption_key: SymmetricKey,
    sender: P2PSender,
    receiver: mpsc::UnboundedReceiver<P2PMessageBody>,
    read_state: ReadState,
}

#[derive(Debug, Clone)]
pub enum ClientSync {
    NewDataCapsule(Hash),
    ReadMetadata(Hash),
    Init,
    Write,
    Commit(Hash),
    Read(Hash),
    Proof(Hash),
    FreshestCommits,
    Records(Hash),
}

#[derive(Debug, Clone)]
pub enum ClientResponse {
    NewDataCapsule,
    ReadMetadata(DataCapsule),
    Init,
    Write,
    Commit,
    Read(Vec<u8>),
    Proof(bool),
    FreshestCommits(Vec<Hash>),
    Records(Vec<Hash>, Hash),
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
            read_state: ReadState::new(),
        };
        (c, s)
    }

    pub fn new_data_capsule_request(
        &self,
        writer_pub_key: &PublicKey,
        description: &str,
    ) -> (Request, ClientSync, Hash) {
        let creator_pub_key = serialize_pubkey(&self.signing_pub_key);
        let writer_pub_key = serialize_pubkey(writer_pub_key);
        let hash = hash_dc_metadata(&creator_pub_key, &writer_pub_key, description);
        let dc = DataCapsule {
            creator_pub_key,
            writer_pub_key,
            description: description.into(),
            signature: sign(&hash, &self.signing_key),
        };
        (
            Request::NewDataCapsule(dc),
            ClientSync::NewDataCapsule(hash),
            hash,
        )
    }

    pub fn read_metadata_request(&self, dc: &Hash) -> (Request, ClientSync) {
        (Request::ReadMetadata(*dc), ClientSync::ReadMetadata(*dc))
    }

    pub fn init_request(&self, dc: &Hash) -> (Request, ClientSync) {
        (Request::Init(*dc), ClientSync::Init)
    }

    pub fn write_request(&self, data: &[u8]) -> (Request, ClientSync, Hash) {
        let encrypted_data = encrypt(data, &self.encryption_key);
        let hash = hash_data(&encrypted_data);
        (Request::Write(encrypted_data), ClientSync::Write, hash)
    }

    pub fn commit_request(
        &self,
        records: &[Hash],
        prev_commit_hash: Hash,
    ) -> (Request, ClientSync, Hash) {
        let root_hash = merkle_tree_root(records, &prev_commit_hash);
        let signature = sign(&root_hash, &self.signing_key);
        (
            Request::Commit(prev_commit_hash, signature),
            ClientSync::Commit(root_hash),
            root_hash,
        )
    }

    pub fn read_request(&self, record: &Hash) -> (Request, ClientSync) {
        (Request::Read(*record), ClientSync::Read(*record))
    }

    pub fn proof_request(&self, record: &Hash) -> (Request, ClientSync) {
        (Request::Proof(*record), ClientSync::Proof(*record))
    }

    pub fn freshest_commits_request(&self) -> (Request, ClientSync) {
        (Request::FreshestCommits, ClientSync::FreshestCommits)
    }

    pub fn records_request(&self, commit: &Hash) -> (Request, ClientSync) {
        (Request::Records(*commit), ClientSync::Records(*commit))
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

    fn response_to_client_response(&mut self, dc_server_key: &PublicKey, resp: Response, sync: &ClientSync) -> ClientResponse {
        match (resp, sync) {
            (Response::NewDataCapsule(sig), ClientSync::NewDataCapsule(hash)) => {
                if verify_signature(&sig, hash, dc_server_key) {
                    ClientResponse::NewDataCapsule
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::ReadMetadata(dc), ClientSync::ReadMetadata(hash)) => {
                if &hash_dc_metadata(&dc.creator_pub_key, &dc.writer_pub_key, &dc.description) == hash {
                    ClientResponse::ReadMetadata(dc)
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::Init, ClientSync::Init) => {
                self.read_state = ReadState::new();
                ClientResponse::Init
            }
            (Response::Write, ClientSync::Write) => ClientResponse::Write,
            (Response::Commit(sig), ClientSync::Commit(hash)) => {
                if verify_signature(&sig, hash, dc_server_key) {
                    ClientResponse::Commit
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::Read(encrypted_data), ClientSync::Read(hash)) => {
                if &hash_data(&encrypted_data) == hash {
                    ClientResponse::Read(decrypt(&encrypted_data, &self.encryption_key))
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::Proof { root, nodes }, ClientSync::Proof(hash)) => {
                let success = verify_proof(
                    hash,
                    &root,
                    &nodes,
                    &self.signing_pub_key,
                    &mut self.read_state,
                )
                .is_ok();
                ClientResponse::Proof(success)
            }
            (Response::FreshestCommits(commits), ClientSync::FreshestCommits) => {
                let mut good = true;
                for (hash, signature) in &commits {
                    if !verify_signature(&signature, &hash, &self.signing_pub_key) {
                        // TODO: use someone else's pubkey
                        good = false;
                        break;
                    }
                }
                if good {
                    let commits = commits.iter().map(|(h, _)| *h).collect();
                    ClientResponse::FreshestCommits(commits)
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            (Response::Records(records, additional), ClientSync::Records(hash)) => {
                if merkle_tree_root(&records, &additional) == *hash {
                    ClientResponse::Records(records, additional)
                } else {
                    ClientResponse::CryptographyFail
                }
            }
            _ => ClientResponse::ServerFail,
        }
    }


}




fn verify_proof(
    expected_hash: &Hash,
    root: &Option<(Signature, Hash)>,
    nodes: &[HashNode],
    writer_public_key: &PublicKey,
    read_state: &mut ReadState,
) -> Result<(), DCClientError> {
    // checks the root signature, checks the hash of each node
    // (adding to the cache as it goes)
    // then checks that the given hash is in the cache

    // if the root is provided, check it for validity and add it to the cache
    if let Some(s) = root {
        if verify_signature(&s.0, &s.1, writer_public_key) {
            read_state.add_signed_hash(&s.1);
        } else {
            return Err(DCClientError::BadSignature);
        }
    }
    // for each node in the chain, check it for validity and add it to the cache
    for b in nodes {
        if read_state.contains(&hash_node(b)) {
            read_state.add_proven_node(b);
        } else {
            return Err(DCClientError::BadProof("node not proven".into()));
        }
    }

    // check that the hash that we want to prove is in the cache
    if read_state.contains(expected_hash) {
        Ok(())
    } else {
        Err(DCClientError::BadProof("hash not proven".into()))
    }
}
