use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use sled::{Db, Error, IVec, Tree};

use crate::crypto::{Hash, HashNode, PublicKey, SignedHash};

fn open_tree(db: Db, prefix: u8, dc_name: &Hash) -> Result<Tree, Error> {
    let mut name = [0; 40]; // multiple of 8 for good luck
    name[0] = prefix;
    name[8..].copy_from_slice(dc_name);
    db.open_tree(name)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredDataCapsule {
    creator_pub_key: Vec<u8>,
    writer_pub_key: Vec<u8>,
    description: String,
    creator_signature: SignedHash,
    latest_record: Hash,
}

// key: datacapsule hash
// value: datacapsule metadata
struct MetaStorage(Tree);
impl MetaStorage {
    fn new(db: Db) -> Result<Self, Error> {
        Ok(Self(db.open_tree(b"M")?))
    }

    fn store(&mut self, dc_name: &Hash, dc: &StoredDataCapsule) -> Result<(), Error> {
        let data = to_stdvec(dc).expect("postcard"); // TODO TODOOOOOOO handle well
        self.0.insert(dc_name, data)?;
        Ok(())
    }

    fn get(&mut self, dc_name: &Hash) -> Result<Option<StoredDataCapsule>, Error> {
        Ok(match self.0.get(dc_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }
}

// key: record hash
// value: record data
struct DataStorage(Tree);
impl DataStorage {
    fn new(db: Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'D', dc_name)?))
    }

    fn store(&mut self, record_name: &Hash, record_data: &[u8]) -> Result<(), Error> {
        self.0.insert(record_name, record_data)?;
        Ok(())
    }

    fn get(&mut self, record_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(record_name)?.map(|d: IVec| d.to_vec()))
    }
}

// key: record hash
// value: {sequence_number, parent}
struct RecordStorage(Tree);
impl RecordStorage {
    fn new(db: Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'R', dc_name)?))
    }

    fn store(
        &mut self,
        record_name: &Hash,
        sequence_number: u64,
        parent: &Hash,
    ) -> Result<(), Error> {
        let mut data = [0; 40];
        data[0..8].copy_from_slice(&sequence_number.to_le_bytes());
        data[8..].copy_from_slice(parent);
        let refdata: &[u8] = &data[0..];
        self.0.insert(record_name, refdata)?;
        Ok(())
    }

    fn get(&mut self, record_name: &Hash) -> Result<Option<(u64, Hash)>, Error> {
        Ok(match self.0.get(record_name)? {
            Some(d) => {
                if d.len() != 40 {
                    None
                } else {
                    let (a, b) = d.split_at(8);
                    let sn = u64::from_le_bytes(a.try_into().expect("arithmetic"));
                    let hash = b.try_into().expect("arithmetic");
                    Some((sn, hash))
                }
            }
            None => None,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredNode {
    parent: Option<Hash>,
    signature: Option<Hash>,
    children: HashNode,
}

// key: node hash
// value {Option<parent>, Option<signature>, children}
struct NodeStorage(Tree);
impl NodeStorage {
    fn new(db: Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'N', dc_name)?))
    }

    fn store(&mut self, node_name: &Hash, node: &StoredNode) -> Result<(), Error> {
        let data = to_stdvec(&node).expect("postcard"); // TODO TODOOOOOOO handle well
        self.0.insert(node_name, data)?;
        Ok(())
    }

    fn get(&mut self, node_name: &Hash) -> Result<Option<StoredNode>, Error> {
        Ok(match self.0.get(node_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }
}

// key: seqno
// value: record hash
struct SequenceStorage(Tree);
impl SequenceStorage {
    fn new(db: Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'S', dc_name)?))
    }

    fn store(&mut self, sequence_number: u64, record_name: &Hash) -> Result<(), Error> {
        self.0.insert(&sequence_number.to_le_bytes(), record_name)?;
        Ok(())
    }

    fn get(&mut self, sequence_number: u64) -> Result<Option<Hash>, Error> {
        Ok(match self.0.get(&sequence_number.to_le_bytes())? {
            Some(d) => (&d[0..]).try_into().ok(),
            None => None,
        })
    }
}
