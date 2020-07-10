use async_trait::async_trait;
use reqwest::{Client, Request, Response};
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
    client: Client,
}

impl HttpCtClient {
    pub fn new<S: Into<String>>(base_url: S) -> Self {
        let client = Client::new();
        Self {
            base_url: base_url.into(),
            client,
        }
    }
}

#[cfg(test)]
const TIMEOUT_MS: u64 = 1;

#[cfg(not(test))]
const TIMEOUT_MS: u64 = 2000;
const REQUEST_CLONE_ERROR: &str =
    "An error occurred cloning the client request, this should not happen.";
const RETRY_LIMIT: u64 = 3;

impl HttpCtClient {
    async fn request(&self, request: Request) -> Result<reqwest::Response, Box<dyn Error>> {
        let mut count = 1;
        loop {
            let request = request.try_clone().ok_or(REQUEST_CLONE_ERROR)?;
            let response = self.client.execute(request).await?;
            match response.status() {
                http::status::StatusCode::OK => return Ok(response),
                _ => {
                    self.handle_error(response, count).await?;
                    count += 1;
                }
            };
        }
    }

    async fn handle_error(&self, response: Response, count: u64) -> Result<(), Box<dyn Error>> {
        let body = response
            .text()
            .await
            .map_or_else(|_| "unknown".into(), |body| body);
        let delay = TIMEOUT_MS * count;
        eprintln!(
            "Retrying in {}ms because an error occurred: {}",
            delay, body
        );
        tokio::time::delay_for(tokio::time::Duration::from_millis(delay)).await;
        if count == RETRY_LIMIT {
            return Err(format!("An error occurred: {}", body).into());
        }
        Ok(())
    }
}

#[async_trait]
impl CtClient for HttpCtClient {
    async fn get_entries(&self, start: usize, end: usize) -> Result<Logs, Box<dyn Error>> {
        let response = self
            .request(
                self.client
                    .get(&format!(
                        "{}/get-entries?start={}&end={}",
                        self.base_url, start, end
                    ))
                    .build()?,
            )
            .await?;
        let logs = response.json::<Logs>().await?;
        if logs.entries.len() < (end - start + 1) {
            return Err("Number of logs retrieved is incorrect".into());
        }
        Ok(logs)
    }

    async fn get_tree_size(&self) -> Result<usize, Box<dyn Error>> {
        let response = self
            .request(
                self.client
                    .get(&format!("{}/get-sth", self.base_url))
                    .build()?,
            )
            .await?;
        Ok(response.json::<STH>().await?.tree_size)
    }
}

#[cfg(test)]
mod test {
    use super::{Logs, STH};
    use crate::client::{CtClient, HttpCtClient, LogEntry};
    use tokio;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[tokio::test]
    async fn get_entries_should_retry_three_times_if_it_fails() {
        let server_error = "oh no, sth retrieval error";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .up_to_n_times(3)
            .expect(3)
            .mount(&mock_server)
            .await;
        let client = HttpCtClient::new(mock_server.uri().to_string());
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_num_entries_should_retry_three_times_if_it_fails() {
        let server_error = "oh no, sth retrieval error";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .up_to_n_times(3)
            .expect(3)
            .mount(&mock_server)
            .await;
        let client = HttpCtClient::new(mock_server.uri().to_string());
        let result = client.get_tree_size().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_num_entries_should_fail_if_api_call_fails() {
        let server_error = "oh no, sth retrieval error";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .mount(&mock_server)
            .await;

        let client = HttpCtClient::new(mock_server.uri().to_string());
        let result = client.get_tree_size().await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("An error occurred: {}", server_error)
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
        let client = HttpCtClient::new(mock_server.uri().to_string());
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
        let client = HttpCtClient::new(mock_server.uri().to_string());
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("An error occurred: {}", server_error)
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
        let client = HttpCtClient::new(mock_server.uri().to_string());
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
        let client = HttpCtClient::new(mock_server.uri().to_string());
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
        let client = HttpCtClient::new(mock_server.uri().to_string());
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}
