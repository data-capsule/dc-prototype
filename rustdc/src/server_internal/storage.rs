use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use sled::{Db, Error, IVec, Tree};

use crate::crypto::{Hash, HashNode, SignedHash};

fn open_tree(db: &Db, prefix: u8, dc_name: &Hash) -> Result<Tree, Error> {
    let mut name = [0; 40]; // multiple of 8 for good luck
    name[0] = prefix;
    name[8..].copy_from_slice(dc_name);
    db.open_tree(name)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredDataCapsule {
    creator_pub_key: Vec<u8>,
    writer_pub_key: Vec<u8>,
    description: String,
    creator_signature: SignedHash,
}

// key: datacapsule hash
// value: datacapsule metadata
pub struct MetaStorage(Tree);
impl MetaStorage {
    pub fn new(db: &Db) -> Result<Self, Error> {
        Ok(Self(db.open_tree(b"M")?))
    }

    pub fn store(&mut self, dc_name: &Hash, dc: &StoredDataCapsule) -> Result<(), Error> {
        let data = to_stdvec(dc).expect("postcard"); // TODO TODOOOOOOO handle well
        self.0.insert(dc_name, data)?;
        Ok(())
    }

    pub fn get(&mut self, dc_name: &Hash) -> Result<Option<StoredDataCapsule>, Error> {
        Ok(match self.0.get(dc_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }

    pub fn get_writer_pk(db: &Db, dc_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(Self::new(db)?.get(dc_name)?.map(|sdc| sdc.writer_pub_key))
    }
}

// key: record hash
// value: encrypted record data
pub struct DataStorage(Tree);
impl DataStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'D', dc_name)?))
    }

    pub fn store(&mut self, record_name: &Hash, record_data: &[u8]) -> Result<(), Error> {
        self.0.insert(record_name, record_data)?;
        Ok(())
    }

    pub fn get(&mut self, record_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(record_name)?.map(|d: IVec| d.to_vec()))
    }
}

// key: record hash
// value: {sequence_number, parent}
pub struct RecordStorage(Tree);
impl RecordStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'R', dc_name)?))
    }

    pub fn store(
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

    pub fn get(&mut self, record_name: &Hash) -> Result<Option<(u64, Hash)>, Error> {
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
pub struct StoredNode {
    pub parent: Option<Hash>,
    pub signature: Option<SignedHash>,
    pub children: HashNode,
}

// key: node hash
// value {Option<parent>, Option<signature>, children}
pub struct NodeStorage(Tree);
impl NodeStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'N', dc_name)?))
    }

    pub fn store(&mut self, node_name: &Hash, node: &StoredNode) -> Result<(), Error> {
        let data = to_stdvec(&node).expect("postcard"); // TODO TODOOOOOOO handle well
        self.0.insert(node_name, data)?;
        Ok(())
    }

    pub fn get(&mut self, node_name: &Hash) -> Result<Option<StoredNode>, Error> {
        Ok(match self.0.get(node_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }
}

// key: seqno
// value: record hash
pub struct SequenceStorage(Tree);
impl SequenceStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'S', dc_name)?))
    }

    pub fn store(&mut self, sequence_number: u64, record_name: &Hash) -> Result<(), Error> {
        self.0.insert(sequence_number.to_le_bytes(), record_name)?;
        Ok(())
    }

    pub fn get(&mut self, sequence_number: u64) -> Result<Option<Hash>, Error> {
        Ok(match self.0.get(sequence_number.to_le_bytes())? {
            Some(d) => (&d[0..]).try_into().ok(),
            None => None,
        })
    }

    pub fn last_hash(&mut self) -> Result<Option<Hash>, Error> {
        Ok(match self.0.last()? {
            Some((_, v)) => (&v[0..]).try_into().ok(),
            None => None,
        })
    }
}
