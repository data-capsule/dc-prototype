use crate::{
    client::DCClientError,
    shared::crypto::{
        encrypt, hash_data, hash_record_header, sign, verify_signature, Hash, PrivateKey,
        PublicKey, Signature, SymmetricKey,
    },
    shared::dc_repr,
};

/// Returns hash/pointer of written record (header).
pub fn write_record(
    dc_name: &Hash,
    encrypted_record_body: &dc_repr::RecordBody,
    prev_record_ptr: &Hash,
    additional_record_ptrs: &Vec<dc_repr::AdditionalRecordPtr>,
) -> Result<Hash, DCClientError> {
    let body_ptr = hash_data(encrypted_record_body);

    // TODO: send request to persist encrypted_record_body body on server

    let record_header = dc_repr::RecordHeader {
        dc_name: *dc_name,
        body_ptr: body_ptr,
        prev_record_ptr: *prev_record_ptr,
        additional_record_ptrs: additional_record_ptrs.clone(),
    };

    let record_ptr = hash_record_header(&record_header);

    // TODO: send request to persist record header on server

    Ok((record_ptr))
}

/// Note that the relevant DataCapsule name is already included in the
/// hash/pointer of the record header.
pub fn sign_record(record_ptr: &Hash, writer_priv_key: &PrivateKey) -> Result<(), DCClientError> {
    let sig = sign(record_ptr, writer_priv_key);

    // TODO: send request to persist signature on server

    Ok(())
}

pub fn request_durability_ack(record_ptrs: &Vec<Hash>) -> Result<(), DCClientError> {
    // TODO: send request to obtain acks from servers

    // TODO: verify acks from servers

    // TODO: throw error if (quorum of?) servers did not ack (timeout?)

    Ok(())
}
