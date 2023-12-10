use std::{collections::HashMap, io, sync::Arc};

use sled::Db;
use tokio::{
    fs::File,
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};

use crate::shared::crypto::{deserialize_private_key_from_pem, PrivateKey};

use fakep2p::{P2PComm, P2PConfig, P2PMessageBody, P2PReceiver, P2PSender};

use super::writer::handle_client;

#[derive(Clone)]
pub(crate) struct ServerContext {
    pub server_name: String,
    pub db: Db,
    pub pk: PrivateKey,
}

pub async fn run_server(name: String, folder: &str) {
    let db = sled::open(folder.to_owned() + "/my_db").unwrap();

    let pk = read_file(folder, "server_private.pem").await.unwrap();
    let pk = deserialize_private_key_from_pem(&pk);

    let net_config = read_file(folder, "net_config.json").await.unwrap();
    let net_config = String::from_utf8(net_config).unwrap();
    let net_config: P2PConfig = serde_json::from_str(&net_config).unwrap();
    let ctx = ServerContext {
        server_name: name.clone(),
        db,
        pk,
    };

    let per_client_pipes = Arc::new(Mutex::new(HashMap::<
        String,
        mpsc::UnboundedSender<P2PMessageBody>,
    >::new()));

    let mut comm = P2PComm::new(name.clone(), net_config).await.unwrap();
    tracing::info!("comm set up");
    loop {
        let ctx = ctx.clone();
        let per_client_pipes = per_client_pipes.clone();
        let rcv = comm.accept().await.unwrap();
        let send = comm.new_sender();
        tracing::info!("accepted a connection");

        tokio::spawn(async move {
            handle(send, rcv, ctx, per_client_pipes).await;
        });
    }
}

pub async fn read_file(folder: &str, name: &str) -> Result<Vec<u8>, io::Error> {
    let mut total = folder.to_owned();
    total.push('/');
    total += name;
    tracing::info!("reading {total}");
    let mut f = File::open(total).await?;
    let mut res = Vec::new();
    f.read_to_end(&mut res).await?;
    Ok(res)
}

async fn handle(
    send: P2PSender,
    mut rcv: P2PReceiver,
    ctx: ServerContext,
    per_client_pipes: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<P2PMessageBody>>>>,
) {
    loop {
        let m = match rcv.receive().await {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                tracing::error!("oh no! {:?}", e);
                return;
            }
            None => {
                tracing::info!("connection ended peacefully");
                return;
            }
        };
        {
            // scope for mutex
            let mut cheese = per_client_pipes.lock().await;
            match cheese.get(&m.sender) {
                Some(s) => s.send(m).unwrap(), // TODO HANDLE WELL
                None => {
                    let ctx = ctx.clone();
                    let (s, r) = mpsc::unbounded_channel();
                    let client_name = m.sender.clone();
                    let new_sender = send.clone();
                    s.send(m).unwrap(); // TODO HANDLE WELL
                    cheese.insert(client_name, s);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(ctx, r, new_sender).await {
                            tracing::error!("oh no {:?}", e);
                        }
                    });
                }
            }
        }
    }
}
