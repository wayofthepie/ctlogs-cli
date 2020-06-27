mod client;
mod persist;
use client::{CtClient, HttpCtClient};
use persist::Store;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

const CTLOGS_LEAF_DIR: &str = ".ctlogs";
const ARGON_CSV_FILE: &str = "argon.csv";
const RETRIEVAL_LIMIT: usize = 30;

async fn execute<P: AsRef<Path>>(dir: P, client: impl CtClient) -> Result<(), Box<dyn Error>> {
    let mut argon_logs_path = PathBuf::from(dir.as_ref());
    argon_logs_path.push(CTLOGS_LEAF_DIR);
    if !std::path::Path::exists(&argon_logs_path) {
        std::fs::create_dir_all(&argon_logs_path)?;
    }
    argon_logs_path.push(ARGON_CSV_FILE);
    let mut store = Store::new(argon_logs_path);
    let count = store.count();
    let mut start = if count == 0 { 0 } else { count - 1 };
    let tree_size = client.get_tree_size().await?;
    let mut end = start
        + if tree_size > RETRIEVAL_LIMIT {
            RETRIEVAL_LIMIT
        } else {
            tree_size - 1
        };
    loop {
        println!("start {} end {}", start, end);
        if end >= tree_size {
            // TODO: we should continue to call tree_size as logs
            // are updated in realtime. This will only work for inactive
            // logs.
            println!("Log is empty.");
            break;
        }
        let logs = client.get_entries(start, end).await?;
        let length = logs.entries.len();
        store.write_logs(logs)?;
        start += length + 1;
        end += length + 1;
    }
    Ok(())
}

const ARGON_CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2020/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = HttpCtClient::new(ARGON_CT_LOGS_URL);
    let dir = "/var/tmp/";
    execute(dir, client).await
}

#[cfg(test)]
mod test {
    use crate::{
        client::{CtClient, LogEntry, Logs},
        execute,
    };
    use async_trait::async_trait;
    use std::{
        fs::OpenOptions,
        io::{BufRead, BufReader},
        path::PathBuf,
    };
    use tempfile::tempdir;
    use tokio;

    const CTLOGS_LEAF: &str = ".ctlogs";
    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[derive(Default)]
    struct FakeCtClient {
        tree_size: usize,
    }

    #[async_trait]
    impl CtClient for FakeCtClient {
        async fn get_entries(
            &self,
            _: usize,
            _: usize,
        ) -> Result<crate::client::Logs, Box<dyn std::error::Error>> {
            let mut entries = Vec::new();
            for _ in 0..self.tree_size {
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
    async fn csv_file_should_contain_tree_size_plus_one_rows_once_complete() {
        let tree_size = 2;
        let expected_rows = 3; // tree_size + header row
        let dir = tempdir().unwrap();
        let mut argon_csv = PathBuf::from(dir.path().clone());
        argon_csv.push(CTLOGS_LEAF);
        argon_csv.push("argon.csv");
        let mut client = FakeCtClient::default();
        client.tree_size = tree_size;
        let result = execute(&dir, client).await;
        let file = OpenOptions::new().read(true).open(argon_csv).unwrap();
        let count = BufReader::new(&file).lines().count();
        assert!(result.is_ok());
        assert_eq!(count, expected_rows);
    }

    #[tokio::test]
    async fn should_create_directory_if_it_doesnt_exist() {
        let dir = tempdir().unwrap();
        let mut expected_dir = PathBuf::from(dir.path().clone());
        expected_dir.push(CTLOGS_LEAF);
        let mut client = FakeCtClient::default();
        client.tree_size = 1;
        let result = execute(&dir, client).await;
        assert!(result.is_ok());
        assert!(
            std::path::Path::exists(&expected_dir),
            "directory {:?} does not exist",
            &expected_dir
        );
    }
}
