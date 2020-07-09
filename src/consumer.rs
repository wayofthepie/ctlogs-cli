use crate::producer::LogsChunk;
use der_parser::ber::{BerObjectContent, BerTag};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use x509_parser::{
    objects::{oid2nid, Nid},
    TbsCertificate,
};

#[derive(Default, Debug, Deserialize, Serialize)]
struct CertInfo {
    pub position: usize,
    pub issuer: String,
    pub subject: String,
    pub san: Vec<SanObject>,
    pub cert: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
enum SanObject {
    Ipv4Addr(String),
    DnsName(String),
}

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
                    // Found precert, ignore.
                    continue;
                } else {
                    let start = 15;
                    let length = u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]);
                    let end = length as usize + start;
                    match x509_parser::parse_x509_der(&bytes[start..end]) {
                        Ok((_, cert)) => {
                            let mut info = extract_cert_info(cert.tbs_certificate, position)?;
                            info.cert = base64::encode(&bytes[start..end]);
                            let bytes = serde_json::to_vec(&info)?;
                            writer.write_all(&bytes).await?;
                            writer.write_all(b"\n").await?;
                        }
                        Err(err) => println!("Error at position {}: {}", position, err),
                    }
                    position += 1;
                }
            }
        }
        writer.shutdown().await?;
        Ok(())
    }
}

fn extract_cert_info(cert: TbsCertificate, position: usize) -> Result<CertInfo, Box<dyn Error>> {
    let mut cert_info = CertInfo::default();
    cert_info.position = position;
    cert_info.issuer = cert.issuer.to_string();
    cert_info.subject = cert.subject.to_string();
    let mut san = Vec::new();
    for extension in cert.extensions {
        if let Ok(Nid::SubjectAltName) = oid2nid(&extension.oid) {
            parse_san(extension.value, &mut san, position)?;
        }
    }
    cert_info.san = san;
    Ok(cert_info)
}

fn parse_san(
    bytes: &[u8],
    san: &mut Vec<SanObject>,
    position: usize,
) -> Result<(), Box<dyn Error>> {
    let (_, obj) = der_parser::parse_der(bytes)?;
    for item in obj.as_sequence()? {
        match item.content {
            BerObjectContent::Unknown(tag, bytes) => match tag.0 {
                // dns name
                2 => san.push(SanObject::DnsName(
                    String::from_utf8_lossy(bytes).to_string(),
                )),
                // ip address
                7 => san.push(SanObject::Ipv4Addr(
                    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
                )),
                other => eprintln!(
                    "Unknown san type {} encountered at position {}",
                    other, position
                ),
            },
            _ => println!("Failed to read subject alternative name: {:?}", obj),
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{CertInfo, Consumer, SanObject};
    use crate::{
        client::{LogEntry, Logs},
        producer::LogsChunk,
    };
    use std::io::Cursor;
    use tokio;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn consume_should_correctly_decode_san_with_ip_and_dns() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert_ip_and_dns_san").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert_eq!(
            info.san,
            vec![
                SanObject::Ipv4Addr("1.33.202.142".to_owned()),
                SanObject::DnsName("1.33.202.142".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn consume_should_store_full_cert() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
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
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let leaf_input_with_invalid_cert =
            include_str!("../resources/leaf_input_with_invalid_cert").trim();
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
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
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
    async fn consume_should_extract_subject_alternative_names() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(
            info.san,
            vec![
                SanObject::DnsName("www.libraryav.com.au".to_owned()),
                SanObject::DnsName("libraryav.com.au".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn consume_should_skip_precerts() {
        let leaf_input = include_str!("../resources/leaf_input_with_precert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn consume_should_extract_subject() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.subject, "CN=www.libraryav.com.au");
    }

    #[tokio::test]
    async fn consume_should_extract_issuer() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
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
