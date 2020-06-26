use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
struct Logs {
    entries: Vec<LogEntry>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
struct LogEntry {
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
    leaf_input: String,
    extra_data: String,
}

async fn get_entries_from(
    base_url: &str,
    start: usize,
) -> Result<Logs, Box<dyn std::error::Error>> {
    let response = reqwest::get(&format!(
        "{}/get-entries?start={}&end={}",
        base_url,
        start,
        start + 31
    ))
    .await?;
    if response.status() != 200 {
        let body = response
            .text()
            .await
            .map_or_else(|_| "unknown".into(), |body| format!("{}", body));
        return Err(format!("An error occurred retrieving logs: {}", body).into());
    }
    let logs = response.json::<Logs>().await?;
    Ok(logs)
}

fn main() {}

#[cfg(test)]
mod test {
    use crate::{get_entries_from, LogEntry, Logs};
    use tokio;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[tokio::test]
    async fn should_fail_if_log_retrieval_fails() {
        let server_error = "oh no";
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "31"))
            .respond_with(ResponseTemplate::new(400).set_body_string(server_error))
            .mount(&mock_server)
            .await;
        let result = get_entries_from(&mock_server.uri(), 0).await;
        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.err().unwrap()),
            format!("An error occurred retrieving logs: {}", server_error)
        );
    }

    #[tokio::test]
    async fn should_fail_if_body_is_not_an_expected_value() {
        let body: Vec<u32> = vec![0, 0];
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let result = get_entries_from(&mock_server.uri(), 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn should_return_logs() {
        let body = Logs {
            entries: vec![LogEntry {
                leaf_input: LEAF_INPUT.to_owned(),
                extra_data: "".to_owned(),
            }],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let result = get_entries_from(&mock_server.uri(), 0).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}

