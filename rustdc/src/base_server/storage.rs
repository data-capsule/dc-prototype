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

// key: datacapsule hash
// value: datacapsule metadata
pub struct MetaStorage(Tree);
impl MetaStorage {
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

    pub fn get(&self, record_name: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(record_name)?.map(|d: IVec| d.to_vec()))
    }
}

// key: record hash
// value: parent hash
pub struct RecordStorage(Tree);
impl RecordStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'R', dc_name)?))
    }

    pub fn store(&mut self, record_name: &Hash, parent: &Hash) -> Result<(), Error> {
        self.0.insert(record_name, parent)?;
        Ok(())
    }

    pub fn get(&self, record_name: &Hash) -> Result<Option<Hash>, Error> {
        Ok(match self.0.get(record_name)? {
            Some(d) => (&d[0..]).try_into().ok(),
            None => None,
        })
    }
}

// key: commit hash
// value: signature
pub struct OrphanStorage(Tree);
impl OrphanStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'O', dc_name)?))
    }

    pub fn replace(
        &self,
        old_commit_name: &Hash,
        commit_name: &Hash,
        signature: &Signature,
    ) -> Result<(), Error> {
        self.0.insert(commit_name, &signature[..])?;
        self.0.remove(old_commit_name)?;
        Ok(())
    }

    pub fn all_orphans(&self) -> Result<Option<Vec<(Hash, Signature)>>, Error> {
        let mut res = Vec::new();
        for r in self.0.iter() {
            let r = r?;
            let k: Option<Hash> = (&r.0[0..]).try_into().ok();
            let v = r.1[..].to_vec();
            match k {
                Some(k) => res.push((k, v)),
                None => return Ok(None),
            }
        }
        Ok(Some(res))
    }
}
