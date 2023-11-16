use crate::{crypto::{Hash, NULL_HASH}, config::{CACHE_SIZE, FANOUT}};


/*
A cache that is synchronized between client and server.
The larger this cache is, the fewer things need to be
re-sent to the client to prove a read
*/
pub struct ReadState {
    hash_cache: [Hash; CACHE_SIZE],
    last_signed_hash: Hash,
    last_proven_block: [Hash; FANOUT]
}


fn cache_index(hash: &Hash) -> usize {
    let index = (hash[0] as usize) 
    | ((hash[1] as usize) << 8)
    | ((hash[2] as usize) << 16)
    | ((hash[3] as usize) << 24);
    index % CACHE_SIZE
}

impl ReadState {
    pub fn new() -> ReadState {
        ReadState { 
            hash_cache: [NULL_HASH; CACHE_SIZE], 
            last_signed_hash: NULL_HASH, 
            last_proven_block: [NULL_HASH; FANOUT]
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        for h in &self.last_proven_block {
            if h == hash {
                return true;
            }
        }
        if &self.hash_cache[cache_index(hash)] == hash {
            return true;
        }
        if &self.last_signed_hash == hash {
            return true;
        }
        false
    } 

    pub fn add_signed_hash(&mut self, hash: &Hash) {
        let old_hash = self.last_signed_hash;
        self.hash_cache[cache_index(&old_hash)] = old_hash;
        self.last_signed_hash = old_hash;
    }

    pub fn add_proven_block(&mut self, hashes: &[Hash; FANOUT]) {
        for h in self.last_proven_block {
            self.hash_cache[cache_index(&h)] = h;
        }
        self.last_proven_block = *hashes;
    }
}