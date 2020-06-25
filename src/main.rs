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

async fn get_entries_from(start: usize) -> Result<Logs, Box<dyn std::error::Error>> {
    let response = reqwest::get(&format!(
        "http://localhost:5000/logs/argon2020/ct/v1/get-entries?start={}&end={}",
        start,
        start + 31
    ))
    .await?;
    if response.status() != 200 {
        return Err("An error occurred retrieving logs".into());
    }
    let logs = response.json::<Logs>().await?;
    Ok(logs)
}

fn main() {}

#[cfg(test)]
mod test {
    use crate::{get_entries_from, LogEntry, Logs};
    use httpmock::Method::GET;
    use httpmock::{mock, with_mock_server};
    use tokio;

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[tokio::test]
    #[with_mock_server]
    async fn should_fail_if_log_retrieval_fails() {
        let _ = mock(GET, "/logs/argon2020/ct/v1/get-entries")
            .expect_query_param("start", "0")
            .expect_query_param("end", "31")
            .return_status(400)
            .create();
        let result = get_entries_from(0).await;
        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.err().unwrap()),
            "An error occurred retrieving logs"
        );
    }

    #[tokio::test]
    #[with_mock_server]
    async fn should_fail_if_body_is_not_an_expected_value() {
        let body = vec![0, 0];
        let _ = mock(GET, "/logs/argon2020/ct/v1/get-entries")
            .expect_query_param("start", "0")
            .expect_query_param("end", "31")
            .return_json_body(&body)
            .return_status(200)
            .create();
        let result = get_entries_from(0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[with_mock_server]
    async fn should_return_logs() {
        let body = Logs {
            entries: vec![LogEntry {
                leaf_input: LEAF_INPUT.to_owned(),
                extra_data: "".to_owned(),
            }],
        };
        let _ = mock(GET, "/logs/argon2020/ct/v1/get-entries")
            .expect_query_param("start", "0")
            .expect_query_param("end", "31")
            .return_json_body(&body)
            .return_status(200)
            .create();
        let result = get_entries_from(0).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}
