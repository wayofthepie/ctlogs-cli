use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Logs {
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogEntry {
    /// The `leaf_input` field is a `String` of base64 encoded data. The data is a DER encoded
    /// MerkleTreeHeader, which has the following structure.
    /// ```
    /// [0] [1] [2..=9] [10..=11] [12..=14] [15..]
    /// |   |     |        |         |      |
    /// |   |     |        |         |      |- rest
    /// |   |     |        |         |      
    /// |   |     |        |         |- length
    /// |   |     |        |               
    /// |   |     |        | - log entry type
    /// |   |     |                       
    /// |   |     | - timestamp
    /// |   |                            
    /// |   | - signature type
    /// |                               
    /// | - version
    /// ```
    ///
    pub leaf_input: String,
    pub extra_data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct STH {
    pub tree_size: usize,
}

#[async_trait]
pub trait CtClient {
    async fn get_entries(&self, start: usize, end: usize) -> Result<Logs, Box<dyn Error>>;
    async fn get_tree_size(&self) -> Result<usize, Box<dyn Error>>;
}

pub struct HttpCtClient {
    base_url: String,
}

impl HttpCtClient {
    pub fn new<S: Into<String>>(base_url: S) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

#[async_trait]
impl CtClient for HttpCtClient {
    async fn get_entries(&self, start: usize, end: usize) -> Result<Logs, Box<dyn Error>> {
        let response = reqwest::get(&format!(
            "{}/get-entries?start={}&end={}",
            self.base_url, start, end
        ))
        .await?;
        if response.status() != 200 {
            let body = response
                .text()
                .await
                .map_or_else(|_| "unknown".into(), |body| body);
            return Err(format!("An error occurred retrieving logs: {}", body).into());
        }
        let logs = response.json::<Logs>().await?;
        if logs.entries.len() < (end - start + 1) {
            return Err("Number of logs retrieved is incorrect".into());
        }
        Ok(logs)
    }

    async fn get_tree_size(&self) -> Result<usize, Box<dyn Error>> {
        let response = reqwest::get(&format!("{}/get-sth", self.base_url)).await?;
        if response.status() != 200 {
            let body = response
                .text()
                .await
                .map_or_else(|_| "unknown".into(), |body| body);
            return Err(format!("An error occurred retrieving sth: {}", body).into());
        }
        Ok(response.json::<STH>().await?.tree_size)
    }
}

#[cfg(test)]
mod test {
    use super::{Logs, STH};
    use crate::{client::LogEntry, CtClient, HttpCtClient};
    use tokio;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[tokio::test]
    async fn get_num_entries_should_fail_if_api_call_fails() {
        let server_error = "oh no, sth retrieval error";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .mount(&mock_server)
            .await;

        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_tree_size().await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("An error occurred retrieving sth: {}", server_error)
        );
    }

    #[tokio::test]
    async fn get_num_entries_should_return_size() {
        let expected_size: usize = 12;
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(STH {
                tree_size: expected_size,
            }))
            .mount(&mock_server)
            .await;

        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_tree_size().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_size);
    }

    #[tokio::test]
    async fn get_entries_should_fail_if_log_retrieval_fails() {
        let server_error = "oh no";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .mount(&mock_server)
            .await;
        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("An error occurred retrieving logs: {}", server_error)
        );
    }

    #[tokio::test]
    async fn get_entries_should_fail_if_body_is_not_an_expected_value() {
        let body: Vec<u32> = vec![0, 0];
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_entries_should_error_if_requested_number_of_logs_does_not_match_actual() {
        let body = Logs {
            entries: vec![LogEntry {
                leaf_input: LEAF_INPUT.to_owned(),
                extra_data: "".to_owned(),
            }],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.err().unwrap()),
            "Number of logs retrieved is incorrect"
        );
    }

    #[tokio::test]
    async fn get_entries_should_return_logs() {
        let body = Logs {
            entries: vec![
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
            ],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let client = HttpCtClient {
            base_url: mock_server.uri(),
        };
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}
