use std::{collections::HashMap, io};
use bytes::{BufMut, BytesMut};
use futures::{StreamExt, SinkExt, stream::SplitStream, FutureExt};
use postcard::{from_bytes, to_stdvec};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use tokio::{sync::mpsc, net::{TcpListener, TcpStream}};
use tokio_util::codec::{Encoder, Decoder, Framed};


type Name = String; // in actuality, should be a hash, but oh well


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2PMessageBody {
    pub dest: Name,
    pub sender: Name,
    pub content: Vec<u8>,
    pub metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2PConfig {
    pub name: Name,
    pub addr_map: HashMap<Name, String>,
    pub mcast_groups: HashMap<Name, Vec<Name>>
}

pub struct P2PComm {
    config: P2PConfig,
    listener: TcpListener,
    senders:  HashMap<Name, mpsc::UnboundedSender<P2PMessageBody>>,
    receivers: HashMap<Name, mpsc::UnboundedReceiver<P2PMessageBody>>,
    connected: Vec<TcpStream>,
}

pub struct P2PReceiver {
    stream: SplitStream<Framed<TcpStream, P2PCodec>>
}

pub struct P2PSender {
    queues: HashMap<Name, mpsc::UnboundedSender<P2PMessageBody>>,
    mcast_groups: HashMap<Name, Vec<Name>>
}


fn io_err<T>(s: &str) -> Result<T, io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, s))
}

fn encode<T: Serialize>(item: T, dst: &mut BytesMut) -> Result<(), io::Error> {
    let cheese = match to_stdvec(&item) {
        Ok(v) => v,
        Err(_) => return io_err("postcard serialization"),
    };
    let message_len: u64 = match cheese.len().try_into() {
        Ok(x) => x,
        Err(_) => return io_err("message len"),
    };
    let message_len = message_len.to_le_bytes();
    dst.reserve(8 + cheese.len());
    dst.put_slice(&message_len);
    dst.put_slice(&cheese);
    Ok(())
}

fn decode<T: Serialize + DeserializeOwned>(src: &mut BytesMut) -> Result<Option<T>, io::Error> {
    if src.len() < 8 {
        return Ok(None);
    }
    let message_len = &src[0..8];
    let message_len = u64::from_le_bytes(message_len.try_into().unwrap());
    let message_len: usize = match message_len.try_into() {
        Ok(x) => x,
        Err(_) => return io_err("message len"),
    };
    if src.len() < 8 + message_len {
        return Ok(None);
    }

    match from_bytes(&src.split_to(8 + message_len)[8..]) {
        Ok(item) => Ok(Some(item)),
        Err(_) => io_err("postcard deserialization"),
    }
}

struct P2PCodec(());

impl P2PCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Encoder<P2PMessageBody> for P2PCodec {
    type Error = io::Error;

    fn encode(&mut self, item: P2PMessageBody, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode(item, dst)
    }
}

impl Decoder for P2PCodec {
    type Item = P2PMessageBody;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode(src)
    }
}


impl P2PComm {
    pub async fn new(mut config: P2PConfig) -> Result<Self, io::Error> {
        let addr = config.addr_map.remove(&config.name).unwrap();
        let listener = TcpListener::bind(&addr).await?;

        let mut receivers = HashMap::new();
        let mut senders = HashMap::new();
        for (n, _) in &config.addr_map {
            let (s, r) = mpsc::unbounded_channel();
            senders.insert(n.clone(), s);
            receivers.insert(n.clone(), r);
        }
        
        let mut connected = Vec::new();
        for (_, addr) in &config.addr_map {
            if let Ok(s) = TcpStream::connect(addr).await {
                connected.push(s);
            }
        }

        Ok(Self { config, listener, senders, receivers, connected })
    }

    /// Waits for a new connection to become available, then accepts it.
    /// In a real p2p network, config might be set so this process connects to
    /// a fixed number of forwarding nodes, or perhaps this process will
    /// dynamically connect to all "nearby" nodes.
    pub async fn accept(&mut self) -> Result<P2PReceiver, io::Error> {
        let stream = if let Some(s) = self.connected.pop() {
            s
        } else {
            self.listener.accept().await?.0
        };

        let cheese = Framed::new(stream, P2PCodec::new());
        let (mut sink, mut stream) = cheese.split();

        // identify ourselves to the other side
        let dummy_msg = P2PMessageBody {
            dest: Name::new(),
            sender: self.config.name.clone(),
            content: Vec::new(),
            metadata: Vec::new(),
        };
        sink.send(dummy_msg).await?;
        let otherside_name = match stream.next().await {
            Some(Ok(m)) => m.sender,
            Some(Err(e)) => return Err(e),
            None => return io_err("no starting message from other side"),
        };

        let mut recv = self.receivers.remove(&otherside_name).unwrap();
        
        tokio::spawn(async move {
            loop {
                let m = match recv.recv().now_or_never() {
                    Some(m) => m,
                    None => {
                        if sink.flush().await.is_err() {
                            return;
                        }
                        recv.recv().await
                    }
                };
                let m = match m {
                    Some(m) => m,
                    None => return,
                };
                if sink.feed(m).await.is_err() {
                    return;
                }
            }
        });
        
        Ok(P2PReceiver { stream })
    }

    pub fn new_sender(&self) -> P2PSender {
        P2PSender {
            queues: self.senders.clone(),
            mcast_groups: self.config.mcast_groups.clone(),
        }
    }
}

impl P2PSender {
    /// Sends a message into the network, to one peer
    pub fn send_one(&mut self, msg: P2PMessageBody) -> Result<(), io::Error> {
        if let Some(sender) = self.queues.get(&msg.dest) {
            if let Err(_) = sender.send(msg) {
                return io_err("mpsc");
            }
        }
        Ok(())
    }

    /// Sends a message into the network, to a group of peers
    pub fn send_multi(&mut self, msg: P2PMessageBody) -> Result<(), io::Error> {
        let group = self.mcast_groups.get(&msg.dest).unwrap();
        for n in group {
            if let Some(sender) = self.queues.get(n) {
                if let Err(_) = sender.send(msg.clone()) {
                    return io_err("mpsc");
                }
            }
        }
        Ok(())
    }
}

impl P2PReceiver {
    /// Receives a message from the network
    pub async fn receive(&mut self) -> Option<Result<P2PMessageBody, io::Error>> {
        self.stream.next().await
    }
}
