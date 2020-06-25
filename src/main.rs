use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Logs {
    entries: Vec<LogEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
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

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::LogEntry;
    use httpmock::Method::GET;
    use httpmock::{mock, with_mock_server, Mock};
    use reqwest;
    use tokio;

    const LEAF_INPUT: &str = include_str!("../resources/leaf_input_with_cert");

    #[tokio::test]
    #[with_mock_server]
    async fn should_call_argon_logs() {
        let logs_mock = mock(GET, "/logs/argon2020/ct/v1/get-entries")
            .expect_query_param("start", "1")
            .expect_query_param("end", "2")
            .return_json_body(&LogEntry {
                leaf_input: LEAF_INPUT.to_owned(),
                extra_data: "".to_owned(),
            })
            .return_status(200)
            .create();

        let response = reqwest::get(&format!(
            "http://localhost:5000/logs/argon2020/ct/v1/get-entries?start={}&end={}",
            1, 2
        ))
        .await
        .expect("failed to get");
        assert_eq!(response.status(), 200)
    }
}
