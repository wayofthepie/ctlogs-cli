mod cli;
pub mod client;
mod consumer;
pub mod parser;
pub mod producer;

use cli::{Fs, Opt};
use client::{CtClient, HttpCtClient};
use consumer::consume;
use producer::{produce, sigint_handler};
use std::error::Error;
use structopt::StructOpt;

const CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2020/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let fs = Fs;
    let config = Opt::from_args().handle(fs).await?;
    let client = HttpCtClient::new(CT_LOGS_URL);
    let tree_size = client.get_tree_size().await?;
    println!("Starting from position {:#?}", config.start);
    let stream = produce(client, config.start, tree_size, sigint_handler);
    consume(stream, config.writer).await
}
