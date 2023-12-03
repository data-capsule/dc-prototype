pub mod reader;
pub mod writer;

#[derive(Debug)]
pub enum DCClientError {
    ServerError(String),
    MismatchedHash,
    BadSignature,
    BadProof(String),
    OpenSSL(openssl::error::ErrorStack),
    IO(std::io::Error),
    StreamEnded,
    Other(String),
}

impl From<std::io::Error> for DCClientError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<openssl::error::ErrorStack> for DCClientError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}
