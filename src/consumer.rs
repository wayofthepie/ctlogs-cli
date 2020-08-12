use crate::{
    parser,
    producer::{LogsChunk, PinnedStream},
};
use futures::StreamExt;
use std::error::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};

pub async fn consume(
    mut stream: PinnedStream<LogsChunk>,
    writer: impl AsyncWrite + Unpin + Send,
) -> Result<(), Box<dyn Error>> {
    let mut writer = BufWriter::new(writer);
    let result = parse_stream(stream, &mut writer).await;
    println!("shutting down gracefully");
    writer.shutdown().await?;
    result
}

async fn parse_stream(
    mut stream: PinnedStream<LogsChunk>,
    mut writer: impl AsyncWrite + Unpin + Send,
) -> Result<(), Box<dyn Error>> {
    while let Some(maybe_chunk) = stream.next().await {
        let LogsChunk { logs, mut position } = maybe_chunk?;
        for entry in logs.entries {
            let bytes = base64::decode(&entry.leaf_input)?;
            let entry_type = bytes[10] + bytes[11];
            if entry_type != 0 {
                eprintln!("Found precert at position {}, ignoring.", position);
            } else {
                let cert_end_index =
                    u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]) as usize + 15;
                match parser::parse_x509_bytes(&bytes[15..cert_end_index], position) {
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
    Ok(())
}

#[cfg(test)]
mod test {
    use super::consume;
    use crate::{
        client::{LogEntry, Logs},
        parser::CertInfo,
        producer::LogsChunk,
    };
    use futures::{stream, StreamExt};
    use std::{io::Cursor, iter};

    #[tokio::test]
    async fn consume_should_store_full_cert() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let mut buf: Vec<u8> = Vec::new();
        let chunk = LogsChunk {
            logs: Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            },
            position: 0,
        };
        let stream = stream::iter(iter::once(Ok(chunk))).boxed_local();
        let result = consume(stream, Cursor::new(&mut buf)).await;
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
        let chunk = LogsChunk {
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
            position: 7777,
        };
        let stream = stream::iter(iter::once(Ok(chunk))).boxed_local();
        let mut buf: Vec<u8> = Vec::new();
        let result = consume(stream, Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert_eq!(info.position, expected_position);
    }

    #[tokio::test]
    async fn consume_should_store_position_of_each_log_entry() {
        let mut position = 7777;
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let chunk = LogsChunk {
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
            position: 7777,
        };
        let stream = stream::iter(iter::once(Ok(chunk))).boxed_local();
        let mut buf: Vec<u8> = Vec::new();
        let result = consume(stream, Cursor::new(&mut buf)).await;
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
        let chunk = LogsChunk {
            logs: Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            },
            position: 0,
        };
        let stream = stream::iter(iter::once(Ok(chunk))).boxed_local();
        let mut buf: Vec<u8> = Vec::new();
        let result = consume(stream, Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn consume_should_error_if_base64_decode_fails() {
        let leaf_input = "#";
        let chunk = LogsChunk {
            logs: Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            },
            position: 0,
        };
        let stream = stream::iter(iter::once(Ok(chunk))).boxed_local();
        let mut buf: Vec<u8> = Vec::new();
        let result = consume(stream, Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }
}
