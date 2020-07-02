mod client;
use async_compression::tokio_02::write::GzipEncoder;
use client::{CtClient, HttpCtClient, Logs};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;
use tokio::{fs::OpenOptions, join, sync::mpsc};

const RETRIEVAL_LIMIT: usize = 31;

async fn consumer<P: AsRef<Path>>(
    path: P,
    mut chan: mpsc::Receiver<Logs>,
) -> Result<(), Box<dyn Error>> {
    let mut path = PathBuf::from(path.as_ref());
    path.push("logs.gz");
    let writer = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(&path)
        .await?;
    let mut gzip = GzipEncoder::new(writer);
    while let Some(logs) = chan.recv().await {
        for entry in logs.entries {
            gzip.write_all(entry.leaf_input.as_bytes()).await?;
            gzip.write_all(b"\n").await?;
        }
    }
    gzip.shutdown().await?;
    Ok(())
}

async fn producer(
    client: Arc<impl CtClient>,
    mut chan: mpsc::Sender<Logs>,
) -> Result<(), Box<dyn Error>> {
    let tree_size = client.get_tree_size().await?;
    let (mut div, rem) = (tree_size / RETRIEVAL_LIMIT, tree_size % RETRIEVAL_LIMIT);
    let mut start = 0;
    let mut end = start + RETRIEVAL_LIMIT - 1;
    let mut queue = FuturesUnordered::new();
    while div != 0 {
        let c = client.clone();
        queue.push(async move {
            // TODO Retry this on failure
            // Also, don't unwrap!
            c.get_entries(start, end).await.unwrap()
        });
        if queue.len() == 12 {
            while let Some(logs) = queue.next().await {
                chan.send(logs).await?;
            }
        }
        start += RETRIEVAL_LIMIT;
        end = start + RETRIEVAL_LIMIT - 1;
        div -= 1;
    }
    while let Some(logs) = queue.next().await {
        chan.send(logs).await?;
    }
    if rem != 0 {
        let logs = client.get_entries(start, start + rem - 1).await?;
        chan.send(logs).await?;
    }
    Ok(())
}

const CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2020/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = HttpCtClient::new(CT_LOGS_URL);
    let (tx, rx) = mpsc::channel(100);
    let (producer_result, consumer_result) =
        join!(producer(Arc::new(client), tx), consumer(".", rx));
    match (producer_result, consumer_result) {
        (Ok(_), Ok(_)) => Ok(()),
        _ => Err("Error occurred!".into()),
    }
}

#[cfg(test)]
mod test {
    use crate::{
        client::{CtClient, LogEntry, Logs},
        consumer, producer,
    };
    use async_compression::tokio_02::bufread::GzipDecoder;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::{self, fs::OpenOptions, io::BufReader, sync::mpsc};

    #[derive(Default)]
    struct FakeCtClient {
        tree_size: usize,
    }

    #[async_trait]
    impl CtClient for FakeCtClient {
        async fn get_entries(
            &self,
            start: usize,
            end: usize,
        ) -> Result<crate::client::Logs, Box<dyn std::error::Error>> {
            let mut entries = Vec::new();
            for _ in start..=end {
                let entry = LogEntry {
                    leaf_input: "".to_owned(),
                    extra_data: "".to_owned(),
                };
                entries.push(entry);
            }
            Ok(Logs { entries })
        }

        async fn get_tree_size(&self) -> Result<usize, Box<dyn std::error::Error>> {
            Ok(self.tree_size)
        }
    }

    #[tokio::test]
    async fn consumer_should_write_items_received_on_channel_compressed_and_separated_with_a_newline(
    ) {
        let expected_data = "test";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.into_path();
        let p = path.clone();
        let (mut tx, rx) = mpsc::channel(100);
        tx.send(Logs {
            entries: vec![LogEntry {
                leaf_input: expected_data.to_owned(),
                extra_data: "".to_owned(),
            }],
        })
        .await
        .unwrap();
        let handle = tokio::spawn(async move { consumer(&p, rx).await.unwrap() });
        drop(tx);
        handle.await.unwrap();
        let mut path = path.to_owned();
        path.push("logs.gz");
        let file = OpenOptions::new().read(true).open(&path).await.unwrap();
        let mut decoder = GzipDecoder::new(BufReader::new(file));
        let mut actual = String::new();
        decoder.read_to_string(&mut actual).await.unwrap();
        assert_eq!(actual, format!("{}\n", expected_data));
    }

    #[tokio::test]
    async fn producer_should_return_all_logs() {
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let (tx, mut rx) = mpsc::channel(100);
        producer(Arc::new(client), tx).await.unwrap();
        let mut count = 0;
        while let Some(logs) = rx.recv().await {
            count += logs.entries.len();
        }
        assert_eq!(count, tree_size)
    }
}
