pub mod client;
mod consumer;
pub mod parser;
pub mod producer;

use client::HttpCtClient;
use consumer::Consumer;
use producer::Producer;
use std::error::Error;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{fs::OpenOptions, sync::mpsc, sync::oneshot, try_join};

const CT_LOGS_URL: &str = "https://ct.googleapis.com/aviator/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("logs")
        .await?;
    let (sigint_tx, sigint_rx) = oneshot::channel();
    let client = Box::new(HttpCtClient::new(CT_LOGS_URL));
    let (tx, rx) = mpsc::channel(2000);
    let producer = Producer::new(client, tx, sigint_rx);
    let mut consumer = Consumer::new(rx);
    match try_join!(
        producer.produce(),
        consumer.consume(writer),
        signal_handler(sigint_tx)
    ) {
        Ok((_, _, _)) => Ok(()),
        errs => Err(format!("Error occurred: {:#?}", errs).into()),
    }
}

async fn signal_handler(signal_tx: oneshot::Sender<()>) -> Result<(), Box<dyn Error>> {
    let mut sigint = signal(SignalKind::interrupt())?;
    sigint.recv().await;
    signal_tx
        .send(())
        .map_err(|_| "Failed to propagate sigint to other tasks!")?;
    eprintln!("Attempting to gracefully let tasks complete.");
    Ok(())
}
