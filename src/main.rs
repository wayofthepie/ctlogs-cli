mod client;
use client::{CtClient, HttpCtClient, Logs};
use std::error::Error;
use tokio::sync::mpsc;

const RETRIEVAL_LIMIT: usize = 31;

async fn producer(
    client: impl CtClient,
    mut chan: mpsc::Sender<Logs>,
) -> Result<(), Box<dyn Error>> {
    let tree_size = client.get_tree_size().await?;
    let (mut div, rem) = (tree_size / RETRIEVAL_LIMIT, tree_size % RETRIEVAL_LIMIT);
    let mut start = 0;
    let mut end = start + RETRIEVAL_LIMIT - 1;
    while div != 0 {
        let logs = client.get_entries(start, end).await?;
        chan.send(logs).await?;
        start += RETRIEVAL_LIMIT;
        end = start + RETRIEVAL_LIMIT - 1;
        div -= 1;
    }
    if rem != 0 {
        let logs = client.get_entries(start, start + rem - 1).await?;
        chan.send(logs).await?;
    }
    Ok(())
}

const ARGON_CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2020/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = HttpCtClient::new(ARGON_CT_LOGS_URL);
    let (tx, _) = mpsc::channel(100);
    producer(client, tx).await
}

#[cfg(test)]
mod test {
    use crate::{
        client::{CtClient, LogEntry, Logs},
        producer,
    };
    use async_trait::async_trait;
    use tokio::{self, sync::mpsc};

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

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
                    leaf_input: LEAF_INPUT.trim().to_owned(),
                    extra_data: "test".to_owned(),
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
    async fn producer_should_return_all_logs() {
        let tree_size = 200;
        let client = FakeCtClient { tree_size };
        let (tx, mut rx) = mpsc::channel(100);
        producer(client, tx).await.unwrap();
        let mut count = 0;
        while let Some(logs) = rx.recv().await {
            count += logs.entries.len();
        }
        assert_eq!(count, tree_size)
    }
}

