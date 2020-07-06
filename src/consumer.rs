use crate::client::Logs;
use async_compression::tokio_02::write::GzipEncoder;
use der_parser::ber::BerObjectContent;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    path::{Path, PathBuf},
    pin::Pin,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::{
    fs::{File, OpenOptions},
    sync::mpsc,
};
use x509_parser::{
    objects::{oid2nid, Nid},
    TbsCertificate,
};

#[derive(Default, Deserialize, Serialize)]
struct CertInfo {
    pub issuer: String,
}

pub struct Consumer {
    logs_rx: mpsc::Receiver<Logs>,
}

impl Consumer {
    pub fn new(logs_rx: mpsc::Receiver<Logs>) -> Self {
        Self { logs_rx }
    }

    #[allow(dead_code)]
    pub async fn consume(
        &mut self,
        writer: impl AsyncWrite + Unpin + Send,
    ) -> Result<(), Box<dyn Error>> {
        let mut gzip = GzipEncoder::new(writer);
        for logs in self.logs_rx.recv().await {
            for entry in logs.entries {
                let bytes = base64::decode(entry.leaf_input)?;
                let start = 15;
                let length = u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]);
                let end = length as usize + start;
                let (_, cert) = x509_parser::parse_x509_der(&bytes[start..end])?;
                let info = CertInfo {
                    issuer: cert.tbs_certificate.issuer.to_string(),
                };
                let bytes = serde_json::to_vec(&info).unwrap();
                gzip.write(&bytes).await?;
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
    async fn consume_should_extract_issuer() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            })
            .await
            .unwrap();
        drop(logs_tx);
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        let info = serde_json::from_slice::<CertInfo>(&decode(&buf).await.unwrap()).unwrap();
        assert!(result.is_ok());
        assert_eq!(info.issuer, "C=US, O=GeoTrust Inc., CN=RapidSSL SHA256 CA");
    }

    #[tokio::test]
    async fn consume_should_error_if_cert_fails_to_parse() {
        let leaf_input = include_str!("../resources/leaf_input_with_invalid_cert").trim();
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            })
            .await
            .unwrap();
        drop(logs_tx);
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn consume_should_error_if_base64_decode_fails() {
        let leaf_input = "#";
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            })
            .await
            .unwrap();
        drop(logs_tx);
        let mut buf: Vec<u8> = Vec::new();
        let result = consumer.consume(Cursor::new(&mut buf)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn consume_should_write_logs_compressed() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let (mut logs_tx, logs_rx) = mpsc::channel(10);
        let mut consumer = Consumer::new(logs_rx);
        logs_tx
            .send(Logs {
                entries: vec![LogEntry {
                    leaf_input: leaf_input.to_owned(),
                    extra_data: "".to_owned(),
                }],
            })
            .await
            .unwrap();
        drop(logs_tx);
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
}
