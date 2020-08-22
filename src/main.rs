mod cli;
pub mod client;
mod consumer;
pub mod parser;
pub mod producer;

use cli::{Fs, Opt};
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
use structopt::StructOpt;
use tokio::signal::unix::{signal, SignalKind};

const CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2020/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let fs = Fs;
    let config = Opt::from_args().handle(fs).await?;
    let client = HttpCtClient::new(CT_LOGS_URL);
    let sigint = AtomicBool::new(false);
    let sigint = Arc::new(sigint);
    let tree_size = client.get_tree_size().await?;
    println!("Starting from position {:#?}", config.start);
    let stream = produce(client, config.start, tree_size, sigint.clone());
    tokio::spawn(signal_handler(sigint.clone()));
    consume(stream, config.writer).await
}

async fn signal_handler(sigint: Arc<AtomicBool>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut signal = signal(SignalKind::interrupt())?;
    signal.recv().await;
    sigint.swap(true, Ordering::SeqCst);
    eprintln!("Attempting to gracefully let tasks complete.");
    Ok(())
}
