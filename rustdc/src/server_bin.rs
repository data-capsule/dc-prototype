use std::error::Error;

use datacapsule::server::withp2p::run_server;
use tracing::Level;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
    // Configure a `tracing` subscriber that logs traces emitted by the chat
    // server.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .with_span_events(FmtSpan::FULL)
        .init();

    run_server("server1".into(), "env").await;
    Ok(())
}
