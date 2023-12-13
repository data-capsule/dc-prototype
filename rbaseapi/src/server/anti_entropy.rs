use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};

pub struct ServerConnection {
    name: String,
    // signing_key: PrivateKey,
    // signing_pub_key: PublicKey,
    // encryption_key: SymmetricKey,
    sender: P2PSender,
    receiver: mpsc::UnboundedReceiver<P2PMessageBody>,
    // proven_hash_cache: Cache<Hash, ()>,
}

// Strategies:
// 1. `Quickcheck`` allows for quick confirmation of complete pairwise consistency.
// 2. `Bloom` tries to converge as efficiently as possible but is not guaranteed to reach complete pairwise consistency.
// 3. `Hanming` is guaranteed to reach complete pairwise consistency.
// 4. `Dynamo` is guaranteed to reach complete pairwise consistency.

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Quickcheck(QuickcheckRequest),
    Bloom(BloomRequest),
    Hanming(HanmingRequest),
    // Dynamo(DynamoRequest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Quickcheck(QuickcheckResponse),
    Bloom(BloomResponse),
    Hanming(HanmingResponse),
    // Dynamo(DynamoResponse),
}

struct QuickcheckRequest {
    requester_heads_hash: Hash
}
struct QuickcheckResponse {
    is_pairwise_consistent: bool
}

struct BloomRequest {
    // "last sync" = point in time when the pair of servers last reached complete consistency with each other.
    requester_records_since_last_sync: Bloom<Hash>
}
struct BloomResponse {
    requester_missing_records: Vec<dc_repr::Record>
}

struct HanmingRequest {
    requester_heads: Vec<Hash>, // aka "sources", i.e. records with no incoming pointers
    requester_roots: Vec<Hash>, // aka "sinks", i.e. records with no outgoing pointers
}
struct HanmingResponse {
    requester_missing_records: Vec<dc_repr::Record>
}

impl ServerConnection {
    
}
