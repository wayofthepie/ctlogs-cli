use crate::client::{CtClient, Logs};
use futures::{stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::{error::Error, sync::Arc};
use tokio::{sync::mpsc, sync::oneshot};

const RETRIEVAL_LIMIT: usize = 32;

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogsChunk {
    pub logs: Logs,
    pub start: usize,
}

impl LogsChunk {
    pub fn new(logs: Logs, start: usize) -> Self {
        Self { logs, start }
    }
}

pub struct Producer {
    client: Arc<Box<dyn CtClient>>,
    logs_tx: mpsc::Sender<LogsChunk>,
    sigint_rx: oneshot::Receiver<()>,
}

impl Producer {
    pub fn new(
        client: Box<dyn CtClient>,
        logs_tx: mpsc::Sender<LogsChunk>,
        sigint_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            logs_tx,
            sigint_rx,
        }
    }

    pub async fn produce(mut self) -> Result<(), Box<dyn Error>> {
        let tree_size = self.client.get_tree_size().await?;
        let (mut div, rem) = (tree_size / RETRIEVAL_LIMIT, tree_size % RETRIEVAL_LIMIT);
        let mut start = 0;
        let mut end = start + RETRIEVAL_LIMIT - 1;
        let mut queue = FuturesUnordered::new();
        let mut interrupted = false;
        while div != 0 {
            if self.sigint_rx.try_recv().is_ok() {
                interrupted = true;
                break;
            }
            let c = self.client.clone();
            queue.push(async move {
                let logs = c.get_entries(start, end).await?;
                Ok::<LogsChunk, Box<dyn Error>>(LogsChunk::new(logs, start))
            });
            if queue.len() == 12 {
                while let Some(Ok(chunk)) = queue.next().await {
                    self.logs_tx.send(chunk).await?;
                }
            }
            start += RETRIEVAL_LIMIT;
            end = start + RETRIEVAL_LIMIT - 1;
            div -= 1;
        }
        while let Some(Ok(chunk)) = queue.next().await {
            self.logs_tx.send(chunk).await?;
        }
        if !interrupted && rem != 0 {
            let logs = self.client.get_entries(start, start + rem - 1).await?;
            self.logs_tx.send(LogsChunk::new(logs, start)).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Producer;
    use crate::client::{CtClient, LogEntry, Logs};
    use async_trait::async_trait;
    use tokio::{
        self,
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
        let mut start = 0;
        while let Some(chunk) = logs_rx.recv().await {
            count += chunk.logs.entries.len();
        }
        assert_eq!(count, tree_size)
    }
}
