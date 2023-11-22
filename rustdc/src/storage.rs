use crate::{crypto::{PublicKey, Signature, Hash}, writestate::{TreeBlock, RecordBlock}};



struct StoredDataCapsule {
    creator_pub_key: PublicKey,
    writer_pub_key: PublicKey,
    description: String,
    creator_signature: Signature,
    latest_record: Hash
}

// treeblock, sigblock

trait StorageLayer {
    fn store_data_capsule(&mut self, dc: &StoredDataCapsule) -> Result<(), ()>;
    fn load_data_capsule(&mut self, name: &Hash) -> Result<StoredDataCapsule, ()>;

    fn store_data_block(&mut self, dc: &Hash, name: &Hash, data: &[u8]) -> Result<(), ()>;
    fn load_data_block(&mut self, dc: &Hash, name: &Hash) -> Result<Vec<u8>, ()>;

    fn store_record_block(&mut self, dc: &Hash, name: &Hash, block: &RecordBlock) -> Result<(), ()>;
    fn load_record_block(&mut self, dc: &Hash, name: &Hash) -> Result<RecordBlock, ()>;

    fn store_tree_block(&mut self, dc: &Hash, name: &Hash, block: &TreeBlock) -> Result<(), ()>;
    fn load_tree_block(&mut self, dc: &Hash, name: &Hash) -> Result<TreeBlock, ()>;

    fn store_signature(&mut self, dc: &Hash, name: &Hash, sig: &Signature) -> Result<(), ()>;
    fn load_signature(&mut self, dc: &Hash, name: &Hash) -> Result<Signature, ()>;
}
