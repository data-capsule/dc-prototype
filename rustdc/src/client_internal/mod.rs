use std::io;

pub mod writer;



pub enum DCError {
    ServerError(String),
    Cryptographic(String),
    IO(io::Error),
    Other(String)
}

impl From<io::Error> for DCError {
    fn from(value: io::Error) -> Self {
        Self::IO(value)
    }
}



pub struct CreatorConnection {

}

impl CreatorConnection {

}






pub struct ReaderConnection {

}

impl ReaderConnection {
    
}

pub struct SubscriberConnection {

}

impl SubscriberConnection {
    
}

