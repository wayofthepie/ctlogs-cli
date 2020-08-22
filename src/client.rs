use async_trait::async_trait;
use http::StatusCode;
use reqwest::{Client, Request};
use serde::{Deserialize, Serialize};
use std::{error::Error, time::Duration};

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

#[derive(Clone)]
pub struct HttpCtClient<'a> {
    base_url: &'a str,
    client: Client,
}

impl<'a> HttpCtClient<'a> {
    pub fn new(base_url: &'a str) -> Self {
        let client = Client::new();
        Self { base_url, client }
    }
}

const REQUEST_CLONE_ERROR: &str =
    "An error occurred cloning the client request, this should not happen.";

impl<'a> HttpCtClient<'a> {
    async fn request(&self, request: Request) -> Result<reqwest::Response, Box<dyn Error>> {
        let request = request.try_clone().ok_or(REQUEST_CLONE_ERROR)?;
        let response = self.client.execute(request).await?;
        match response.status() {
            StatusCode::OK => Ok(response),
            _ => Err("Did not receive a 200 OK response, bailing out.".into()),
        }
    }
}

#[async_trait]
impl<'a> CtClient for HttpCtClient<'a> {
    async fn get_entries(&self, start: usize, end: usize) -> Result<Logs, Box<dyn Error>> {
        let response = self
            .request(
                self.client
                    .get(&format!(
                        "{}/get-entries?start={}&end={}",
                        self.base_url, start, end
                    ))
                    .timeout(Duration::from_secs(20))
                    .build()?,
            )
            .await?;
        let mut logs = response.json::<Logs>().await?;
        while logs.entries.len() < end - start + 1 {
            let len = logs.entries.len();
            let new_start = start + len;
            let next = self.get_entries(new_start, end).await?;
            logs.entries.extend(next.entries);
        }
        Ok(logs)
    }

    async fn get_tree_size(&self) -> Result<usize, Box<dyn Error>> {
        let response = self
            .request(
                self.client
                    .get(&format!("{}/get-sth", self.base_url))
                    .timeout(Duration::from_secs(20))
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
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const LEAF_INPUT: &str = include_str!("../resources/test/leaf_input_with_cert");

    #[tokio::test]
    async fn get_num_entries_should_fail_if_api_call_fails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri);
        let result = client.get_tree_size().await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "Did not receive a 200 OK response, bailing out."
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
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri);
        let result = client.get_tree_size().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_size);
    }

    #[tokio::test]
    async fn get_entries_should_fail_if_log_retrieval_fails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "Did not receive a 200 OK response, bailing out.",
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
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
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
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}
