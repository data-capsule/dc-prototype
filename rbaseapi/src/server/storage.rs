use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use sled::{Db, Error, IVec, Tree};
use std::collections::HashSet;

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
#[derive(Clone)]
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

#[derive(Clone)]
pub struct RecordHeaderStorage{
    headers: Tree, // key: record name (hash/pointer of record header), value: record header
    reverse_ptrs: Tree, // key: record name, value: HashSet<names of records that point to key>
    marked: Tree, // key: "HEADS" or "ROOTS", value: HashSet<record names that are {key}>
    replica_buffer: Tree, // key: server name, value: record names stored since last sync.
    // TODO: clean up / put at higher level
}
impl RecordHeaderStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self{
            headers: open_tree(db, b'H', dc_name)?,
            reverse_ptrs: open_tree(db, b'R', dc_name)?,
            marked: open_tree(db, b'A', dc_name)?,
            replica_buffer: open_tree(db, b'E', dc_name)?,
        })
    }

    pub fn store(
        &mut self,
        record_name: &Hash,
        record_header: &dc_repr::RecordHeader,
    ) -> Result<(), Error> {
        self.headers.insert(record_name, to_stdvec(record_header).expect("postcard"))?; // TODO handle well

        // TODO: replace this with range querying over timestamps for more storage efficiency
        for replica_name in self.replica_buffer.iter().keys() {
            let replica_name = replica_name?;
            self.replica_buffer.fetch_and_update(replica_name,
                |old_set_bytes: Option<&[u8]>| -> Option<Vec<u8>> {
                    let mut old_set: HashSet<Hash> = match old_set_bytes {
                        Some(d) => from_bytes(d).expect("postcard de hashset"), // TODO handle well
                        None => HashSet::new(),
                    };
                    old_set.insert(*record_name);
                    Some(to_stdvec(&old_set).expect("postcard")) // TODO handle well
                },
            )?;
        }

        let mut heads = self.get_heads()?;
        let mut roots = self.get_roots()?;

        for backptr in &record_header.record_backptrs {
            self.reverse_ptrs.fetch_and_update(backptr.ptr, 
                |old_set_bytes: Option<&[u8]>| -> Option<Vec<u8>> {
                    let mut old_set: HashSet<Hash> = match old_set_bytes {
                        Some(d) => from_bytes(d).expect("postcard de hashset"), // TODO handle well
                        None => HashSet::new(),
                    };
                    old_set.insert(*record_name);
                    Some(to_stdvec(&old_set).expect("postcard")) // TODO handle well
                },
            )?;

            heads.remove(&backptr.ptr);
        }

        // TODO: better error handling of get_incoming_ptrs
        for record_with_pointer_to_new in &self.get_incoming_ptrs(record_name)?.unwrap_or(HashSet::new()) {
            roots.remove(record_with_pointer_to_new);
        }

        // Add new heads.
        // Note the new record_header is not necessarily a new head - it might be filling a hole.
        // The new heads are ALL SINKS (no outgoing edges) of the REVERSE sub-DAG rooted at the new record.
        // TODO: double-check that we're correctly updating PHYSICAL heads/roots
        // (i.e. records this server actually has currently, NOT logical "true global" state).
        // Note the current way we update `reverse_ptrs` could add mappings for headers this server doesn't have yet.
        // TODO: this may be a lot of I/O overhead.
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut stack: Vec<Hash> = Vec::from([*record_name]);
        while !stack.is_empty() {
            let curr = stack.pop().unwrap();
            if visited.contains(&curr) {
                continue;
            }

            visited.insert(curr);

            let mut is_curr_reverse_sink = true;
            for reverse_child in &self.get_incoming_ptrs(&curr)?.unwrap_or(HashSet::new()) {
                // remember we're checking for PHYSICAL heads
                if let Ok(Some(_)) = self.get(&reverse_child) {
                    is_curr_reverse_sink = false;
                    stack.push(*reverse_child);
                }
            }
            if is_curr_reverse_sink {
                heads.insert(curr);
            }
        }
        self.set_heads(heads)?;

        // Add new roots.
        // The new roots are ALL SINKS (no outgoing edges) of the ORIGINAL sub-DAG rooted at the new record.
        // TODO: this may be a lot of I/O overhead.
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut stack: Vec<Hash> = Vec::from([*record_name]);
        while !stack.is_empty() {
            let curr = stack.pop().unwrap();
            if visited.contains(&curr) {
                continue;
            }

            visited.insert(curr);

            let mut is_curr_sink = true;
            if let Ok(Some(curr_header)) = self.get(&curr) {
                for child in &curr_header.record_backptrs {
                    // remember we're checking for PHYSICAL roots
                    if let Ok(Some(_)) = self.get(&child.ptr) {
                        is_curr_sink = false;
                        stack.push(child.ptr);
                    }
                }
            }
            if is_curr_sink {
                roots.insert(curr);
            }
        }
        self.set_roots(roots)?;

        Ok(())
    }

    pub fn get(&self, record_name: &Hash) -> Result<Option<dc_repr::RecordHeader>, Error> {
        Ok(match self.headers.get(record_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }

    pub fn get_incoming_ptrs(&self, record_name: &Hash) -> Result<Option<HashSet<Hash>>, Error> {
        Ok(match self.reverse_ptrs.get(record_name)? {
            Some(d) => from_bytes(&d).ok(),
            None => None,
        })
    }

    pub fn get_heads(&self) -> Result<HashSet<Hash>, Error> {
        match self.marked.get("HEADS")? {
            Some(d) => Ok(from_bytes(&d).expect("postcard")),
            None => Ok(HashSet::new()),
        }
    }

    pub fn get_roots(&self) -> Result<HashSet<Hash>, Error> {
        match self.marked.get("ROOTS")? {
            Some(d) => Ok(from_bytes(&d).expect("postcard")),
            None => Ok(HashSet::new()),
        }
    }

    pub fn set_heads(&self, heads: HashSet<Hash>) -> Result<(), Error> {
        self.marked.insert("HEADS", to_stdvec(&heads).expect("postcard"))?; // TODO handle well
        Ok(())
    }

    pub fn set_roots(&self, roots: HashSet<Hash>) -> Result<(), Error> {
        self.marked.insert("ROOTS", to_stdvec(&roots).expect("postcard"))?; // TODO handle well
        Ok(())
    }

    pub fn start_tracking_replica(&self, replica_name: String) -> Result<(), Error> {
        // TODO: cleaner way to do this
        let mut all_local_records: HashSet<Hash> = HashSet::new();
        for record_name in self.headers.iter().keys() {
            let record_name = from_bytes(&record_name?).expect("postcard");
            all_local_records.insert(record_name);
        }
        self.replica_buffer.insert(replica_name, to_stdvec(&all_local_records).expect("postcard"))?;
        Ok(())
    }

    pub fn get_buffered_records(&self, replica_name: String) -> Result<HashSet<Hash>, Error> {
        match self.replica_buffer.get(replica_name)? {
            Some(d) => Ok(from_bytes(&d).expect("postcard")),
            None => Ok(HashSet::new()),
        }
    }

    // TODO: check safety under concurrency
    pub fn clear_buffered_records(&self, replica_name: String) -> Result<(), Error> {
        self.replica_buffer.fetch_and_update(replica_name,
            |_: Option<&[u8]>| -> Option<Vec<u8>> {
                let cleared_set: HashSet<Hash> = HashSet::new();
                Some(to_stdvec(&cleared_set).expect("postcard")) // TODO handle well
            },
        )?;
        Ok(())
    }
}

// TODO: find better way to do this
pub fn init_marked(db: &Db, dc_name: &Hash) -> Result<(), Error> {
    let marked = open_tree(db, b'A', dc_name)?;
    marked.insert("HEADS", to_stdvec(&HashSet::from([dc_name])).expect("postcard"))?;
    marked.insert("ROOTS", to_stdvec(&HashSet::from([dc_name])).expect("postcard"))?;
    Ok(())
}

// key: hash/pointer of record **body**, NOT record name / hash of header
// value: record body (encrypted)
#[derive(Clone)]
pub struct RecordBodyStorage(Tree);
impl RecordBodyStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'B', dc_name)?))
    }

    pub fn store(
        &mut self,
        record_body_ptr: &Hash,
        record_body: &dc_repr::RecordBody,
    ) -> Result<(), Error> {
        self.0.insert(record_body_ptr, &record_body[..])?;
        Ok(())
    }

    pub fn get(&self, record_body_ptr: &Hash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(record_body_ptr)?.map(|d: IVec| d.to_vec()))
    }
}

// key: record name (hash/pointer of record header)
// value: witness (see dc_repr::RecordWitness)
#[derive(Clone)]
pub struct RecordWitnessStorage(Tree);
impl RecordWitnessStorage {
    pub fn new(db: &Db, dc_name: &Hash) -> Result<Self, Error> {
        Ok(Self(open_tree(db, b'W', dc_name)?))
    }

    // returns previous value.
    // threadsafe wrt the single given record.
    // note some postcard errors get ignored (wrapped up into RecordWitness::None).
    pub fn update_record_witness(
        &mut self,
        record_name: &Hash,
        new_proposed_witness: &dc_repr::RecordWitness,
    ) -> Result<dc_repr::RecordWitness, Error> {
        let r = self.0.fetch_and_update(
            record_name,
            |old_witness_bytes: Option<&[u8]>| -> Option<Vec<u8>> {
                let old_witness = match old_witness_bytes {
                    Some(d) => from_bytes(d).ok().into(),
                    None => dc_repr::RecordWitness::None,
                };
                // TODO: save cost of reserializing if closer_witness is old_witness?
                let closer_witness =
                    dc_repr::RecordWitness::closer(&old_witness, new_proposed_witness);
                Some(to_stdvec(closer_witness).expect("postcard")) // TODO handle well
            },
        )?;
        // TODO: find better way to unwrap into RecordWitness (note we need RecordWitness::None to do comparisons)
        Ok(match r {
            Some(d) => from_bytes(&d).ok().into(),
            None => dc_repr::RecordWitness::None,
        })
    }

    pub fn get(&self, record_name: &Hash) -> Result<dc_repr::RecordWitness, Error> {
        Ok(match self.0.get(record_name)? {
            Some(d) => from_bytes(&d).ok().into(),
            None => dc_repr::RecordWitness::None,
        })
    }
}
