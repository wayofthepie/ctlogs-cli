use crate::client::{CtClient, Logs};
use futures::{stream, Future, Stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{error::Error, pin::Pin};
use tokio::signal::unix::{signal, SignalKind};

const CONCURRENCY_LEVEL: usize = 12;
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

pub type PinnedStream<T> = Pin<Box<dyn Stream<Item = Result<T, Box<dyn Error>>>>>;

pub fn produce<F, Fut>(
    client: impl CtClient + Clone + Send + Sync + 'static,
    seen: usize,
    tree_size: usize,
    sigint_handler: F,
) -> PinnedStream<LogsChunk>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send + 'static,
{
    stream::iter(gen_iterator(seen, tree_size))
        .map_ok(move |(start, end)| {
            let c = client.clone();
            async move {
                let logs = c.get_entries(start, end).await?;
                Ok::<LogsChunk, Box<dyn Error>>(LogsChunk::new(logs, start))
            }
        })
        .take_until(sigint_handler())
        .try_buffer_unordered(CONCURRENCY_LEVEL)
        .boxed()
}

fn gen_iterator(
    seen: usize,
    tree_size: usize,
) -> impl Iterator<Item = Result<(usize, usize), Box<dyn Error>>> {
    let remaining = tree_size - seen;
    let (num_iterations, rem) = (remaining / RETRIEVAL_LIMIT, remaining % RETRIEVAL_LIMIT);
    (0..=num_iterations).map(move |iteration| {
        let start = iteration * RETRIEVAL_LIMIT + seen;
        let end = if iteration == num_iterations {
            start + rem - 1
        } else {
            start + RETRIEVAL_LIMIT - 1
        };
        Ok((start, end))
    })
}

pub async fn sigint_handler() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut signal = signal(SignalKind::interrupt())?;
    signal.recv().await;
    eprintln!("\nAttempting to gracefully let tasks complete.\n");
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{produce, sigint_handler};
    use crate::client::{CtClient, LogEntry, Logs};
    use async_trait::async_trait;
    use futures::{future, StreamExt};
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
    async fn producer_should_start_at_given_position() {
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let f = || future::ok(());
        let mut stream = produce(client, 10, tree_size, f);
        let mut position = 10;
        let mut logs = Vec::new();
        while let Some(chunk) = stream.next().await {
            logs.push(chunk.unwrap());
        }
        logs.sort_by(|a, b| a.position.cmp(&b.position));
        for chunk in logs {
            let len = chunk.logs.entries.len();
            println!("{:#?} p {}", chunk.position, position);
            assert_eq!(chunk.position, position);
            position += len;
        }
    }

    #[tokio::test]
    async fn producer_should_gracefully_shutdown_on_receiving_sigint() {
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let f = || future::ok(());
        let stream = produce(client, 0, tree_size, f);
        let result = timeout_at(
            Instant::now() + Duration::from_millis(10),
            stream.into_future(),
        )
        .await;
        if result.is_err() {
            panic!("Did not handle signal in 10ms!")
        }
    }

    #[tokio::test]
    async fn producer_should_return_all_logs_with_position() {
        let tree_size = 2341;
        let client = FakeCtClient { tree_size };
        let mut stream = produce(client, 0, tree_size, sigint_handler);
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
