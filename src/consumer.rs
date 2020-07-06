use crate::client::Logs;
use async_compression::tokio_02::write::GzipEncoder;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Default, Deserialize, Serialize)]
struct CertInfo {
    pub issuer: String,
    pub subject: String,
}

pub struct Consumer {
    logs_rx: mpsc::Receiver<Logs>,
}

impl Consumer {
    #[allow(dead_code)]
    pub fn new(logs_rx: mpsc::Receiver<Logs>) -> Self {
        Self { logs_rx }
    }

    #[allow(dead_code)]
    pub async fn consume(
        &mut self,
        writer: impl AsyncWrite + Unpin + Send,
    ) -> Result<(), Box<dyn Error>> {
        let mut gzip = GzipEncoder::new(writer);
        while let Some(logs) = self.logs_rx.recv().await {
            for entry in logs.entries {
                let bytes = base64::decode(entry.leaf_input)?;
                let entry_type = bytes[10] + bytes[11];
                if entry_type != 0 {
                    // Found precert, ignore.
                    continue;
                } else {
                    let start = 15;
                    let length = u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]);
                    let end = length as usize + start;
                    let (_, cert) = x509_parser::parse_x509_der(&bytes[start..end])?;
                    let info = CertInfo {
                        issuer: cert.tbs_certificate.issuer.to_string(),
                        subject: cert.tbs_certificate.subject.to_string(),
                    };
                    let bytes = serde_json::to_vec(&info).unwrap();
                    gzip.write(&bytes).await?;
                }
            }
        }
        gzip.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{CertInfo, Consumer};
    use crate::client::{LogEntry, Logs};
    use async_compression::tokio_02::bufread::GzipDecoder;
    use std::{error::Error, io::Cursor};
    use tokio;
    use tokio::{
        io::{AsyncReadExt, BufReader},
        sync::mpsc,
    };

    #[tokio::test]
    async fn consume_should_skip_precerts() {
        let leaf_input = include_str!("../resources/leaf_input_with_precert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn consume_should_extract_subject() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&decode(&buf).await.unwrap()).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.subject, "CN=www.libraryav.com.au");
    }

    #[tokio::test]
    async fn consume_should_extract_issuer() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&decode(&buf).await.unwrap()).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.issuer, "C=US, O=GeoTrust Inc., CN=RapidSSL SHA256 CA");
    }

    #[tokio::test]
    async fn consume_should_error_if_cert_fails_to_parse() {
        let leaf_input = include_str!("../resources/leaf_input_with_invalid_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn consume_should_error_if_base64_decode_fails() {
        let leaf_input = "#";
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn consume_should_write_logs_compressed() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let mut consumer = init_consumer_with(leaf_input).await;
        let mut buf: Vec<u8> = Vec::new();
        consumer.consume(Cursor::new(&mut buf)).await.unwrap();
        let result = decode(&buf).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    async fn decode(gzipped_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut decoder = GzipDecoder::new(BufReader::new(gzipped_data));
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn init_consumer_with(cert: &str) -> Consumer {
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let consumer = Consumer::new(logs_rx);
        logs_tx
            .send(Logs {
                entries: vec![LogEntry {
                    leaf_input: cert.to_owned(),
                    extra_data: "".to_owned(),
                }],
            })
            .await
            .unwrap();
        drop(logs_tx);
        consumer
    }
}
