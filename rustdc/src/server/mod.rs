mod storage;
mod client_thread;
pub mod withp2p;

#[derive(Debug)]
pub enum DCServerError {
    Cryptographic(String),
    OpenSSL(openssl::error::ErrorStack),
    IO(std::io::Error),
    Storage(sled::Error),
    MissingStorage(String),
    Other(String),
}

impl From<std::io::Error> for DCServerError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<openssl::error::ErrorStack> for DCServerError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

impl From<sled::Error> for DCServerError {
    fn from(value: sled::Error) -> Self {
        Self::Storage(value)
    }
}
