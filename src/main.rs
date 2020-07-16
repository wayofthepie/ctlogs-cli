pub mod client;
mod consumer;
pub mod parser;
pub mod producer;

use client::{CtClient, HttpCtClient};
use consumer::consume;
use producer::produce;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::{fs::OpenOptions, try_join};

const CT_LOGS_URL: &str = "https://ct.googleapis.com/aviator/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("logs")
        .await?;
    let client = HttpCtClient::new(CT_LOGS_URL);
    let sigint = AtomicBool::new(false);
    let sigint = Arc::new(sigint);
    let tree_size = client.get_tree_size().await?;
    let stream = produce(client, tree_size, sigint.clone());
    match try_join!(consume(stream, writer), signal_handler(sigint.clone())) {
        Ok(((), ())) => Ok(()),
        errs => Err(format!("{:?}", errs).into()),
    }
}

async fn signal_handler(sigint: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    let mut signal = signal(SignalKind::interrupt())?;
    signal.recv().await;
    sigint.swap(true, Ordering::SeqCst);
    eprintln!("Attempting to gracefully let tasks complete.");
    Ok(())
}
