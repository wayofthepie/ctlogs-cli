use crate::{parser, producer::LogsChunk};
use std::error::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub struct Consumer {
    chunk_rx: mpsc::Receiver<LogsChunk>,
}

impl Consumer {
    pub fn new(chunk_rx: mpsc::Receiver<LogsChunk>) -> Self {
        Self { chunk_rx }
    }

    pub async fn consume(
        &mut self,
        mut writer: impl AsyncWrite + Unpin + Send,
    ) -> Result<(), Box<dyn Error>> {
        while let Some(LogsChunk { logs, mut position }) = self.chunk_rx.recv().await {
            for entry in logs.entries {
                let bytes = base64::decode(&entry.leaf_input)?;
                let entry_type = bytes[10] + bytes[11];
                if entry_type != 0 {
                    eprintln!("Found precert at position {}, ignoring.", position);
                } else {
                    let cert_end_index = u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]);
                    match parser::parse_x509_bytes(&bytes[15..], cert_end_index as usize, position)
                    {
                        Ok(info) => {
                            let bytes = serde_json::to_vec(&info)?;
                            writer.write_all(&bytes).await?;
                            writer.write_all(b"\n").await?;
                        }
                        Err(err) => eprintln!("Error at position {}: {}", position, err),
                    }
                }
                position += 1;
            }
        }
        writer.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Consumer;
    use crate::{
        client::{LogEntry, Logs},
        parser::CertInfo,
        producer::LogsChunk,
    };
    use std::io::Cursor;
    use tokio;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn consume_should_store_full_cert() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        let leaf_bytes = base64::decode(leaf_input.as_bytes()).unwrap();
        let start = 15;
        let length = u32::from_be_bytes([0, leaf_bytes[12], leaf_bytes[13], leaf_bytes[14]]);
        let end = start + length as usize;
        let cert_bytes = &leaf_bytes[start..end];
        let cert = base64::encode(cert_bytes);
        assert_eq!(info.cert, cert);
    }

    #[tokio::test]
    async fn consume_should_skip_cert_if_it_fails_to_parse() {
        let start_position = 7777;
        let expected_position = start_position + 1;
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let leaf_input_with_invalid_cert =
            include_str!("../resources/test/leaf_input_with_invalid_cert").trim();
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(LogsChunk {
                logs: Logs {
                    entries: vec![
                        LogEntry {
                            leaf_input: leaf_input_with_invalid_cert.to_owned(),
                            extra_data: "".to_owned(),
                        },
                        LogEntry {
                            leaf_input: leaf_input.to_owned(),
                            extra_data: "".to_owned(),
                        },
                    ],
                },
                position: start_position,
            })
            .await
            .unwrap();
        drop(logs_tx);
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert_eq!(info.position, expected_position);
    }

    #[tokio::test]
    async fn consume_should_store_position_of_each_log_entry() {
        let mut position = 7777;
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(LogsChunk {
                logs: Logs {
                    entries: vec![
                        LogEntry {
                            leaf_input: leaf_input.to_owned(),
                            extra_data: "".to_owned(),
                        },
                        LogEntry {
                            leaf_input: leaf_input.to_owned(),
                            extra_data: "".to_owned(),
                        },
                    ],
                },
                position,
            })
            .await
            .unwrap();
        drop(logs_tx);
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let deserialize = serde_json::Deserializer::from_slice(&buf);
        assert!(result.is_ok());
        for info in deserialize.into_iter::<CertInfo>() {
            assert_eq!(info.unwrap().position, position);
            position += 1;
        }
    }

    #[tokio::test]
    async fn consume_should_skip_precerts() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_precert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn consume_should_extract_subject() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.subject, "CN=www.libraryav.com.au");
    }

    #[tokio::test]
    async fn consume_should_extract_issuer() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.issuer, "C=US, O=GeoTrust Inc., CN=RapidSSL SHA256 CA");
    }

    #[tokio::test]
    async fn consume_should_error_if_base64_decode_fails() {
        let leaf_input = "#";
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }

    async fn init_consumer_with(cert: &str) -> Consumer {
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let consumer = Consumer::new(logs_rx);
        logs_tx
            .send(LogsChunk {
                logs: Logs {
                    entries: vec![LogEntry {
                        leaf_input: cert.to_owned(),
                        extra_data: "".to_owned(),
                    }],
                },
                position: 0,
            })
            .await
            .unwrap();
        drop(logs_tx);
        consumer
    }
}
