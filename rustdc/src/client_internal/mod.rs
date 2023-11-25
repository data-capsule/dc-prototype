use std::io;

use openssl::error::ErrorStack;

pub mod creator;
pub mod reader;
pub mod subscriber;
pub mod writer;

pub enum DCError {
    ServerError(String),
    Cryptographic(String),
    OpenSSL(ErrorStack),
    IO(io::Error),
    Other(String),
}

impl From<io::Error> for DCError {
    fn from(value: io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<ErrorStack> for DCError {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}
