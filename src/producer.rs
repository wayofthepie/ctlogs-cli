use crate::client::{CtClient, Logs};
use futures::{stream, Stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const RETRIEVAL_LIMIT: usize = 32;

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogsChunk {
    pub logs: Logs,
    pub position: usize,
}

impl LogsChunk {
    pub fn new(logs: Logs, position: usize) -> Self {
        Self { logs, position }
    }
}

const CONCURRENCY_LEVEL: usize = 12;

pub type PinnedStream<T> = Pin<Box<dyn Stream<Item = Result<T, Box<dyn Error>>>>>;

pub fn produce(
    client: impl CtClient + Clone + Send + Sync + 'static,
    tree_size: usize,
    sigint: Arc<AtomicBool>,
) -> PinnedStream<LogsChunk> {
    stream::iter(gen_iterator(tree_size))
        .map_ok(move |(start, end)| {
            let c = client.clone();
            let s = sigint.clone();
            async move {
                if s.load(Ordering::SeqCst) {
                    return Err("SIGINT received".into());
                }
                let logs = c.get_entries(start, end).await?;
                Ok::<LogsChunk, Box<dyn Error>>(LogsChunk::new(logs, start))
            }
        })
        .try_buffer_unordered(CONCURRENCY_LEVEL)
        .boxed()
}

fn gen_iterator(tree_size: usize) -> impl Iterator<Item = Result<(usize, usize), Box<dyn Error>>> {
    let (num_iterations, rem) = (tree_size / RETRIEVAL_LIMIT, tree_size % RETRIEVAL_LIMIT);
    (0..=num_iterations).map(move |iteration| {
        let start = iteration * RETRIEVAL_LIMIT;
        let end = if iteration == num_iterations {
            start + rem - 1
        } else {
            start + RETRIEVAL_LIMIT - 1
        };
        Ok((start, end))
    })
}

#[cfg(test)]
mod test {
    use super::produce;
    use crate::client::{CtClient, LogEntry, Logs};
    use async_trait::async_trait;
    use futures::StreamExt;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::{
        self,
        time::{timeout_at, Duration, Instant},
    };

    #[derive(Clone, Default)]
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
        let sigint = Arc::new(AtomicBool::new(false));
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let stream = produce(client, tree_size, sigint.clone());
        sigint.store(true, Ordering::SeqCst);
        let result = timeout_at(
            Instant::now() + Duration::from_millis(10),
            stream.into_future(),
        )
        .await;
        if result.is_err() {
            assert!(false, "Did not handle signal in 10ms!")
        }
    }

    #[tokio::test]
    async fn producer_should_return_all_logs_with_position() {
        let sigint = Arc::new(AtomicBool::new(false));
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let mut stream = produce(client, tree_size, sigint);
        let mut position = 0;
        let mut logs = Vec::new();
        while let Some(chunk) = stream.next().await {
            logs.push(chunk.unwrap());
        }
        logs.sort_by(|a, b| a.position.cmp(&b.position));
        for chunk in logs {
            let len = chunk.logs.entries.len();
            assert_eq!(chunk.position, position);
            position += len;
        }
        assert_eq!(position, tree_size)
    }
}
