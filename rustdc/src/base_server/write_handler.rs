use sled::Db;

use crate::shared::crypto::{
    deserialize_pubkey, hash_data, hash_record_header, sign, verify_signature, Hash, PrivateKey,
    PublicKey, Signature,
};

use super::storage::{
    DCMetadataStorage, RecordBodyStorage, RecordHeaderStorage, RecordWitnessStorage,
};
use super::DCServerError;
