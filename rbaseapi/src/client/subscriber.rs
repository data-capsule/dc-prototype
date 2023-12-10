use std::net::SocketAddr;

use futures::SinkExt;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::shared::{
    crypto::{verify_signature, Hash, PublicKey},
    merkle::merkle_tree_root,
    request::{ClientCodec, InitRequest, Request, Response, SubscribeRequest},
};

use super::{initialize_connection, next_response, DCClientError};

pub struct SubscriberConnection {
    writer_pub_key: PublicKey,
    connection: Framed<TcpStream, ClientCodec>,
}

impl SubscriberConnection {
    pub async fn new(
        datacapsule_name: Hash,
        server_address: SocketAddr,
        writer_pub_key: PublicKey,
    ) -> Result<Self, DCClientError> {
        let connection =
            initialize_connection(server_address, InitRequest::Subscribe(datacapsule_name)).await?;
        Ok(Self {
            writer_pub_key,
            connection,
        })
    }

    /// Returns the commit heads of all branches in the datacapsule.
    /// Verifies signatures for all returned commits.
    pub async fn freshest_commits(&mut self) -> Result<Vec<Hash>, DCClientError> {
        let req = Request::Subscribe(SubscribeRequest::FreshestCommits());
        self.connection.send(req).await?;
        match next_response(&mut self.connection).await? {
            Response::SubscribeCommits(commits) => {
                let good_commits = Vec::new();
                for (hash, signature) in commits {
                    if !verify_signature(&signature, &hash, &self.writer_pub_key) {
                        return Err(DCClientError::BadSignature);
                    }
                }
                Ok(good_commits)
            }
            Response::Failed => Err(DCClientError::ServerError("server failed".into())),
            _ => Err(DCClientError::ServerError("mismatched response".into())),
        }
    }

    /// Returns the records in a commit, and the hash of the previous commit.
    /// Verifies that the records match the hash of the commit.
    pub async fn records(&mut self, commit_name: Hash) -> Result<(Vec<Hash>, Hash), DCClientError> {
        let req = Request::Subscribe(SubscribeRequest::Records(commit_name));
        self.connection.send(req).await?;
        match next_response(&mut self.connection).await? {
            Response::SubscribeRecords(records, prev_commit) => {
                if commit_name == merkle_tree_root(&records, &prev_commit) {
                    Ok((records, prev_commit))
                } else {
                    Err(DCClientError::MismatchedHash)
                }
            }
            Response::Failed => Err(DCClientError::ServerError("server failed".into())),
            _ => Err(DCClientError::ServerError("mismatched response".into())),
        }
    }
}
