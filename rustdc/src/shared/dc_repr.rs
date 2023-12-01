use serde::{Deserialize, Serialize};

use crate::shared::crypto::{Signature, Hash};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metadata {
    pub creator_pub_key: Vec<u8>,
    pub writer_pub_key: Vec<u8>,
    pub description: String,
    pub signature: Signature,
}

pub type RecordBody = [u8];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordHeader {
    pub dc_name: Hash,  // "GDP name"
    pub body_ptr: Hash,
    pub prev_record_ptr: Hash,
    pub additional_record_ptrs: Vec<AdditionalRecordPtr>
}

// TODO: not super sure about this
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdditionalRecordPtr {
    pub ptr: Hash,
    pub offset: Option<u64>  // num hops from current record to this `ptr`
}
