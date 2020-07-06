use crate::client::{CtClient, Logs};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{error::Error, sync::Arc};
use tokio::{sync::mpsc, sync::oneshot};

const RETRIEVAL_LIMIT: usize = 32;

pub struct Producer {
    client: Arc<Box<dyn CtClient>>,
    logs_tx: mpsc::Sender<Logs>,
    sigint_rx: oneshot::Receiver<()>,
}

impl Producer {
    pub fn new(
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
        while let Some(logs) = logs_rx.recv().await {
            count += logs.entries.len();
        }
        assert_eq!(count, tree_size)
    }
}
