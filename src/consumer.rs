use crate::client::Logs;
use async_compression::tokio_02::write::GzipEncoder;
use der_parser::ber::BerObjectContent;
use std::{
    error::Error,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;
use tokio::{
    fs::{File, OpenOptions},
    sync::mpsc,
};
use x509_parser::{
    objects::{oid2nid, Nid},
    TbsCertificate,
};

pub struct Consumer {
    logs_rx: mpsc::Receiver<Logs>,
}

impl Consumer {
    pub fn new(logs_rx: mpsc::Receiver<Logs>) -> Self {
        Self { logs_rx }
    }

    pub async fn consume<P: AsRef<Path>>(mut self, path: P) -> Result<(), Box<dyn Error>> {
        let mut path = PathBuf::from(path.as_ref());
        path.push("logs.gz");
        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path)
            .await?;
        let mut gzip = GzipEncoder::new(writer);
        while let Some(logs) = self.logs_rx.recv().await {
            for entry in logs.entries {
                let bytes = base64::decode(entry.leaf_input.clone())?;
                if bytes[10] + bytes[11] != 0 {
                    // Found precert, ignore.
                    continue;
                } else {
                    let cert_start_byte = 15;
                    let length = u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]);
                    let end = length as usize + cert_start_byte;
                    let (_, cert) = x509_parser::parse_x509_der(&bytes[cert_start_byte..end])?;
                    let info = extract_info(cert.tbs_certificate)?;
                    write_compressed(&mut gzip, info, &bytes[cert_start_byte..end]).await?;
                }
            }
        }
        gzip.shutdown().await?;
        Ok(())
    }
}

async fn write_compressed(
    gzip: &mut GzipEncoder<File>,
    info: CertInfo,
    cert: &[u8],
) -> Result<(), Box<dyn Error>> {
    gzip.write_all(info.issuer.as_bytes()).await?;
    gzip.write_all(b"|").await?;
    gzip.write_all(info.subject.as_bytes()).await?;
    gzip.write_all(b"|").await?;
    gzip.write_all(info.subject_alt_names[0].as_bytes()).await?;
    for san in info.subject_alt_names[1..].iter() {
        gzip.write_all(b",").await?;
        gzip.write_all(san.as_bytes()).await?;
    }
    gzip.write_all(b"|").await?;
    gzip.write_all(base64::encode(cert).as_bytes()).await?;
    gzip.write_all(b"\n").await?;
    Ok(())
}

struct CertInfo {
    issuer: String,
    subject: String,
    subject_alt_names: Vec<String>,
}

impl CertInfo {
    fn new(issuer: String, subject: String, subject_alt_names: Vec<String>) -> Self {
        Self {
            issuer,
            subject,
            subject_alt_names,
        }
    }
}

fn extract_info(tbs_certificate: TbsCertificate) -> Result<CertInfo, Box<dyn Error>> {
    let mut sans = Vec::new();
    let issuer = tbs_certificate.issuer.to_string();
    let subject = tbs_certificate.subject.to_string();
    for extension in tbs_certificate.extensions {
        match oid2nid(&extension.oid) {
            Ok(Nid::SubjectAltName) => {
                let (_, obj) = der_parser::parse_der(extension.value)?;
                obj.as_sequence()?
                    .into_iter()
                    .for_each(|item| match item.content {
                        BerObjectContent::Unknown(_, bytes) => {
                            sans.push(String::from_utf8_lossy(bytes).to_string());
                        }
                        _ => println!("Failed to read subject alternative name: {:?}", obj),
                    });
            }
            _ => (),
        }
    }
    Ok(CertInfo::new(issuer, subject, sans))
}

#[cfg(test)]
mod test {
    use crate::{
        client::{LogEntry, Logs},
        Consumer,
    };
    use async_compression::tokio_02::bufread::GzipDecoder;
    use std::{
        error::Error,
        path::{Path, PathBuf},
    };
    use tokio::io::AsyncReadExt;
    use tokio::{
        self,
        fs::{File, OpenOptions},
        io::BufReader,
        sync::mpsc,
    };

    #[tokio::test]
    async fn consumer_should_write_full_cert() {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let bytes = base64::decode(leaf_input).unwrap();
        let cert = base64::encode(&bytes[15..=1666]);
        let actual = execute_and_read_result().await.unwrap();
        assert_eq!(actual[3], cert);
    }

    #[tokio::test]
    async fn consumer_should_write_subject_alt_names() {
        let actual = execute_and_read_result().await.unwrap();
        let expected = "www.libraryav.com.au,libraryav.com.au";
        assert_eq!(actual[2], expected);
    }

    #[tokio::test]
    async fn consumer_should_write_subject() {
        let actual = execute_and_read_result().await.unwrap();
        let expected = "CN=www.libraryav.com.au";
        assert_eq!(actual[1], expected);
    }

    #[tokio::test]
    async fn consumer_should_write_issuer() {
        let actual = execute_and_read_result().await.unwrap();
        let expected = "C=US, O=GeoTrust Inc., CN=RapidSSL SHA256 CA";
        assert_eq!(
            actual[0], expected,
            "{}does not start with: {}",
            actual[0], expected
        );
    }

    #[tokio::test]
    async fn consumer_should_ignore_precerts() {
        let cert = include_str!("../resources/leaf_input_with_precert").trim();
        let path = tmpdir();
        let p = path.clone();
        let (mut tx, rx) = mpsc::channel(100);
        let consumer = Consumer::new(rx);
        tx.send(Logs {
            entries: vec![LogEntry {
                leaf_input: cert.to_owned(),
                extra_data: "".to_owned(),
            }],
        })
        .await
        .unwrap();
        let handle = tokio::spawn(async move { consumer.consume(&p).await.unwrap() });
        drop(tx);
        handle.await.unwrap();
        let mut path = path.to_owned();
        path.push("logs.gz");
        let mut actual = String::new();
        decoder(&path)
            .await
            .read_to_string(&mut actual)
            .await
            .unwrap();
        assert_eq!(actual.lines().count(), 0);
    }

    #[tokio::test]
    async fn consumer_should_write_items_received_on_channel_compressed_and_separated_with_a_newline(
    ) {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let path = tmpdir();
        let p = path.clone();
        let (mut tx, rx) = mpsc::channel(100);
        tx.send(Logs {
            entries: vec![LogEntry {
                leaf_input: leaf_input.to_owned(),
                extra_data: "".to_owned(),
            }],
        })
        .await
        .unwrap();
        let handle = tokio::spawn(async move { Consumer::new(rx).consume(&p).await.unwrap() });
        drop(tx);
        handle.await.unwrap();
        let mut path = path.to_owned();
        path.push("logs.gz");
        let mut actual = String::new();
        decoder(&path)
            .await
            .read_to_string(&mut actual)
            .await
            .unwrap();
        assert_eq!(actual.lines().count(), 1);
    }

    fn tmpdir() -> PathBuf {
        let dir = tempfile::tempdir().unwrap();
        dir.into_path()
    }

    async fn decoder<P: AsRef<Path>>(path: P) -> GzipDecoder<BufReader<File>> {
        let file = OpenOptions::new().read(true).open(&path).await.unwrap();
        GzipDecoder::new(BufReader::new(file))
    }

    async fn execute_and_read_result() -> Result<Vec<String>, Box<dyn Error>> {
        let leaf_input = include_str!("../resources/leaf_input_with_cert").trim();
        let path = tmpdir();
        let p = path.clone();
        let (mut tx, rx) = mpsc::channel(100);
        tx.send(Logs {
            entries: vec![LogEntry {
                leaf_input: leaf_input.to_owned(),
                extra_data: "".to_owned(),
            }],
        })
        .await
        .unwrap();
        let handle = tokio::spawn(async move { Consumer::new(rx).consume(&p).await.unwrap() });
        drop(tx);
        handle.await.unwrap();
        let mut path = path.to_owned();
        path.push("logs.gz");
        let mut actual = String::new();
        decoder(&path)
            .await
            .read_to_string(&mut actual)
            .await
            .unwrap();
        Ok(actual
            .split("|")
            .into_iter()
            .map(|s| s.trim().to_owned())
            .collect())
    }
}
