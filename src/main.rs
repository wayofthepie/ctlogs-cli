pub mod client;
mod consumer;
mod producer;

use client::HttpCtClient;
use consumer::Consumer;
use producer::Producer;
use std::error::Error;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{fs::OpenOptions, join, sync::mpsc, sync::oneshot};

const CT_LOGS_URL: &str = "https://ct.googleapis.com/aviator/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let writer = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("logs.gz")
        .await?;
    let (sigint_tx, sigint_rx) = oneshot::channel();
    let client = Box::new(HttpCtClient::new(CT_LOGS_URL));
    let (tx, rx) = mpsc::channel(2000);
    let mut consumer = Consumer::new(rx);
    let (producer_result, consumer_result, sigint_result) = join!(
        Producer::new(client, tx, sigint_rx).produce(),
        consumer.consume(writer),
        signal_handler(sigint_tx)
    );
    match (producer_result, consumer_result, sigint_result) {
        (Ok(_), Ok(_), Ok(_)) => Ok(()),
        errs => Err(format!("Error occurred: {:#?}", errs).into()),
    }
}

async fn signal_handler(signal_tx: oneshot::Sender<()>) -> Result<(), Box<dyn Error>> {
    let mut sigint = signal(SignalKind::interrupt())?;
    sigint.recv().await;
    if signal_tx.send(()).is_err() {
        println!("An error occurred propagating signal to tasks!");
    }
    println!("Attempting to gracefully let tasks complete.");
    Ok(())
}
