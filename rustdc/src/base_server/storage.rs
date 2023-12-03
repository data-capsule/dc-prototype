use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use sled::{Db, Error, IVec, Tree};

use crate::shared::crypto::{Hash, Signature};
use crate::shared::dc_repr;

fn open_tree(db: &Db, prefix: u8, dc_name: &Hash) -> Result<Tree, Error> {
    let mut name = [0; 40]; // multiple of 8 for good luck
    name[0] = prefix;
    name[8..].copy_from_slice(dc_name);
    db.open_tree(name)
}

// key: datacapsule name
// value: datacapsule metadata
pub struct DCMetadataStorage(Tree);
impl DCMetadataStorage {
    pub fn new(db: &Db) -> Result<Self, Error> {
        Ok(Self(db.open_tree(b"M")?))
    }

    pub fn store(&mut self, dc_name: &Hash, dc: &dc_repr::Metadata) -> Result<(), Error> {
        let data = to_stdvec(dc).expect("postcard"); // TODO handle well
        self.0.insert(dc_name, data)?;
        Ok(())
    }

    pub fn get(&self, dc_name: &Hash) -> Result<Option<dc_repr::Metadata>, Error> {
        Ok(match self.0.get(dc_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }

    pub fn get_writer_pk(db: &Db, dc_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(Self::new(db)?.get(dc_name)?.map(|sdc| sdc.writer_pub_key))
    }
}

// key: record name (hash/pointer of record header)
// value: record header
pub struct RecordHeaderStorage(Tree);
impl RecordHeaderStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'H', dc_name)?))
    }

    pub fn store(&mut self, record_name: &Hash, record_header: &dc_repr::RecordHeader) -> Result<(), Error> {
        let data = to_stdvec(record_header).expect("postcard"); // TODO handle well
        self.0.insert(record_name, data)?;
        Ok(())
    }

    pub fn get(&self, record_name: &Hash) -> Result<Option<dc_repr::RecordHeader>, Error> {
        Ok(match self.0.get(record_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }
}

// key: record name (hash/pointer of record **header**)
// value: record body (encrypted)
pub struct RecordBodyStorage(Tree);
impl RecordBodyStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'B', dc_name)?))
    }

    pub fn store(&mut self, record_name: &Hash, record_body: &dc_repr::RecordBody) -> Result<(), Error> {
        self.0.insert(record_name, record_body)?;
        Ok(())
    }

    pub fn get(&self, record_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(record_name)?.map(|d: IVec| d.to_vec()))
    }
}

// key: record name (hash/pointer of record header)
// value: witness (see dc_repr::RecordWitness)
pub struct RecordWitnessStorage(Tree);
impl RecordWitnessStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'W', dc_name)?))
    }

    pub fn store(&mut self, record_name: &Hash, witness: &dc_repr::RecordWitness) -> Result<(), Error> {
        let data = to_stdvec(witness).expect("postcard"); // TODO handle well
        self.0.insert(record_name, data)?;
        Ok(())
    }

    pub fn get(&self, record_name: &Hash) -> Result<Option<dc_repr::RecordWitness>, Error> {
        Ok(match self.0.get(record_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }
}
