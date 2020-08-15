use std::{error::Error, path::PathBuf};
use structopt::StructOpt;
use tokio::{fs::OpenOptions, io::AsyncWrite};

#[derive(Debug, StructOpt)]
pub struct Opt {
    #[structopt(parse(from_os_str))]
    store: PathBuf,

    #[structopt(long, short)]
    position: usize,
}

pub struct StoreConfig {
    pub start: usize,
    pub writer: Box<dyn AsyncWrite + Unpin + Send + Sync>,
}

impl Opt {
    pub async fn handle(&self) -> Result<StoreConfig, Box<dyn Error>> {
        let mut open_opts = OpenOptions::new();
        let file = open_opts
            .create(true)
            .append(true)
            .open(&self.store)
            .await?;
        Ok(StoreConfig {
            start: self.position,
            writer: Box::new(file),
        })
    }
}
