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
use tokio::signal::unix::{signal, SignalKind};
use tokio::{fs::OpenOptions, join, sync::mpsc, sync::oneshot};

const RETRIEVAL_LIMIT: usize = 32;
const CT_LOGS_URL: &str = "https://ct.googleapis.com/aviator/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (sigint_tx, sigint_rx) = oneshot::channel();
    let client = Box::new(HttpCtClient::new(CT_LOGS_URL));
    let (tx, rx) = mpsc::channel(100);
    let (producer_result, consumer_result, sigint_result) = join!(
        Producer::new(client, tx, sigint_rx).produce(),
        Consumer::new(rx).consume("."),
        signal_handler(sigint_tx)
    );
    match (producer_result, consumer_result, sigint_result) {
        (Ok(_), Ok(_), Ok(_)) => Ok(()),
        (Err(e), _, _) => Ok(println!("{:#?}", e)),
        _ => Err("Error occurred!".into()),
    }
}

struct Producer {
    client: Arc<Box<dyn CtClient>>,
    logs_tx: mpsc::Sender<Logs>,
    sigint_rx: oneshot::Receiver<()>,
}

impl Producer {
    fn new(
        client: Box<dyn CtClient>,
        logs_tx: mpsc::Sender<Logs>,
        sigint_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            logs_tx,
            sigint_rx,
        }
    }

    async fn produce(mut self) -> Result<(), Box<dyn Error>> {
        let tree_size = self.client.get_tree_size().await?;
        let (mut div, rem) = (tree_size / RETRIEVAL_LIMIT, tree_size % RETRIEVAL_LIMIT);
        let mut start = 0;
        let mut end = start + RETRIEVAL_LIMIT - 1;
        let mut queue = FuturesUnordered::new();
        let mut interrupted = false;
        while div != 0 {
            if let Ok(_) = self.sigint_rx.try_recv() {
                interrupted = true;
                break;
            }
            let c = self.client.clone();
            queue.push(async move {
                let logs = c.get_entries(start, end).await?;
                Ok::<Logs, Box<dyn Error>>(logs)
            });
            if queue.len() == 12 {
                while let Some(Ok(logs)) = queue.next().await {
                    self.logs_tx.send(logs).await?;
                }
            }
            start += RETRIEVAL_LIMIT;
            end = start + RETRIEVAL_LIMIT - 1;
            div -= 1;
        }
        while let Some(Ok(logs)) = queue.next().await {
            self.logs_tx.send(logs).await?;
        }
        if !interrupted && rem != 0 {
            let logs = self.client.get_entries(start, start + rem - 1).await?;
            self.logs_tx.send(logs).await?;
        }
        Ok(())
    }
}

struct Consumer {
    logs_rx: mpsc::Receiver<Logs>,
}

impl Consumer {
    fn new(logs_rx: mpsc::Receiver<Logs>) -> Self {
        Self { logs_rx }
    }

    async fn consume<P: AsRef<Path>>(mut self, path: P) -> Result<(), Box<dyn Error>> {
        let mut path = PathBuf::from(path.as_ref());
        path.push("logs.gz");
        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path)
            .await?;
        let mut gzip = GzipEncoder::new(writer);
        while let Some(logs) = self.logs_rx.recv().await {
            for entry in logs.entries {
                gzip.write_all(entry.leaf_input.as_bytes()).await?;
                gzip.write_all(b"\n").await?;
            }
        }
        gzip.shutdown().await?;
        Ok(())
    }
}

async fn signal_handler(signal_tx: oneshot::Sender<()>) -> Result<(), Box<dyn Error>> {
    let mut sigint = signal(SignalKind::interrupt())?;
    sigint.recv().await;
    if let Err(_) = signal_tx.send(()) {
        println!("An error occurred propagating signal to tasks!");
    }
    println!("Attempting to gracefully let tasks complete.");
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        client::{CtClient, LogEntry, Logs},
        Consumer, Producer,
    };
    use async_compression::tokio_02::bufread::GzipDecoder;
    use async_trait::async_trait;
    use tokio::io::AsyncReadExt;
    use tokio::{
        self,
        fs::OpenOptions,
        io::BufReader,
        sync::{mpsc, oneshot},
        time::{timeout_at, Duration, Instant},
    };

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
        let handle = tokio::spawn(async move { Consumer::new(rx).consume(&p).await.unwrap() });
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
    async fn producer_should_gracefully_shutdown_on_receiving_sigint() {
        let tree_size = 2341;
        let client = Box::new(FakeCtClient { tree_size });
        let (logs_tx, _) = mpsc::channel(100);
        let (sigint_tx, sigint_rx) = oneshot::channel();
        let handle = Producer::new(client, logs_tx, sigint_rx).produce();
        sigint_tx.send(()).unwrap();
        if let Err(_) = timeout_at(Instant::now() + Duration::from_millis(10), handle).await {
            assert!(false, "Did not handle signal in 10ms!")
        }
    }

    #[tokio::test]
    async fn producer_should_return_all_logs() {
        let tree_size = 2341;
        let client = Box::new(FakeCtClient { tree_size });
        let (logs_tx, mut logs_rx) = mpsc::channel(100);
        let (_sigint_tx, sigint_rx) = oneshot::channel();
        Producer::new(client, logs_tx, sigint_rx)
            .produce()
            .await
            .unwrap();
        let mut count = 0;
        while let Some(logs) = logs_rx.recv().await {
            count += logs.entries.len();
        }
        assert_eq!(count, tree_size)
    }
}
