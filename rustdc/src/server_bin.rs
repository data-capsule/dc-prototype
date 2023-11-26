use std::env;
use std::error::Error;

use datacapsule::server::run_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    // Configure a `tracing` subscriber that logs traces emitted by the chat
    // server.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("server=info".parse()?))
        .with_span_events(FmtSpan::FULL)
        .init();

    let args: Vec<String> = env::args().collect();
    let (addr, db_file, pk_file) = match args.len() {
        1 => (
            "127.0.0.1:6142".into(),
            "env/my_db".into(),
            "env/server_private.pem".into(),
        ),
        4 => (args[1].clone(), args[2].clone(), args[3].clone()),
        _ => {
            println!("3 arguments required: addr, db, pk");
            return Ok(());
        }
    };

    run_server(addr, db_file, pk_file).await
}
