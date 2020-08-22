use crate::parser::EntryType;
use async_trait::async_trait;
use std::{
    error::Error,
    path::{Path, PathBuf},
};
use structopt::StructOpt;
use tokio::stream::StreamExt;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader},
};

#[derive(Debug, StructOpt)]
pub struct Opt {
    #[structopt(parse(from_os_str))]
    store: PathBuf,
}

pub struct StoreConfig {
    pub start: usize,
    pub writer: Box<dyn AsyncWrite + Unpin + Send + Sync>,
}

impl Opt {
    pub async fn handle(&self, fs: impl FsHandler) -> Result<StoreConfig, Box<dyn Error>> {
        if fs.exists(&self.store).await && fs.size(&self.store).await? > 0 {
            let mut opts = OpenOptions::new();
            let file = fs.open(&self.store, opts.read(true)).await?;
            let reader = BufReader::new(file);
            let max = get_last_position(reader).await?;
            let mut opts = OpenOptions::new();
            let file = fs.open(&self.store, opts.append(true)).await?;
            return Ok(StoreConfig {
                start: max + 1,
                writer: Box::new(file),
            });
        }
        Ok(StoreConfig {
            start: 0,
            writer: Box::new(fs.create(&self.store).await?),
        })
    }
}

async fn get_last_position(reader: BufReader<impl AsyncRead>) -> Result<usize, Box<dyn Error>> {
    let result = reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| {
            let maybe_entry = serde_json::from_str::<EntryType>(&line);
            maybe_entry
                .map(|entry_type| match entry_type {
                    EntryType::X509(info) => info.position,
                    EntryType::PreCert(pre_cert) => pre_cert.position,
                })
                .map_err(|_| "failed to parse cert info".into())
        })
        .collect::<Result<Vec<usize>, Box<dyn Error>>>()
        .await?;
    let max = result.into_iter().max().unwrap_or(0);
    Ok(max)
}

#[async_trait]
pub trait FsHandler {
    type F: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;

    async fn exists<P>(&self, path: P) -> bool
    where
        P: AsRef<Path> + Send + Sync;

    async fn create<P>(&self, path: P) -> Result<Self::F, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync;

    async fn open<P>(&self, path: P, options: &mut OpenOptions) -> Result<Self::F, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync;

    async fn size<P>(&self, path: P) -> Result<u64, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync;
}

pub struct Fs;

#[async_trait]
impl FsHandler for Fs {
    type F = File;
    async fn exists<P>(&self, path: P) -> bool
    where
        P: AsRef<Path> + Send + Sync,
    {
        path.as_ref().exists()
    }

    async fn create<P>(&self, path: P) -> Result<Self::F, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync,
    {
        Ok(File::create(path.as_ref()).await?)
    }

    async fn open<P>(&self, path: P, options: &mut OpenOptions) -> Result<Self::F, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync,
    {
        Ok(options.open(path.as_ref()).await?)
    }

    async fn size<P>(&self, path: P) -> Result<u64, Box<dyn Error>>
    where
        P: AsRef<Path> + Send + Sync,
    {
        Ok(tokio::fs::metadata(path).await?.len())
    }
}

#[cfg(test)]
mod test {
    use super::{FsHandler, Opt};
    use async_trait::async_trait;
    use error::Error;
    use std::io::Cursor;
    use std::{
        collections::HashMap,
        error,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use structopt::StructOpt;
    use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

    struct FakeFs {
        files: Arc<Mutex<HashMap<PathBuf, String>>>,
    }

    impl FakeFs {
        fn new() -> Self {
            let files = Arc::new(Mutex::new(HashMap::new()));
            Self { files }
        }

        fn from_map(map: HashMap<PathBuf, String>) -> Self {
            Self {
                files: Arc::new(Mutex::new(map)),
            }
        }
    }

    #[async_trait]
    impl FsHandler for FakeFs {
        type F = Cursor<Vec<u8>>;

        async fn exists<P>(&self, path: P) -> bool
        where
            P: AsRef<Path> + Send + Sync,
        {
            let path = path.as_ref().to_owned();
            self.files.lock().await.contains_key(&path)
        }

        async fn create<P>(&self, path: P) -> Result<Self::F, Box<dyn Error>>
        where
            P: AsRef<std::path::Path> + Send + Sync,
        {
            self.files
                .lock()
                .await
                .insert(path.as_ref().to_owned(), "".to_owned());
            Ok(std::io::Cursor::new(vec![]))
        }

        async fn open<P>(&self, path: P, _: &mut OpenOptions) -> Result<Self::F, Box<dyn Error>>
        where
            P: AsRef<Path> + Send + Sync,
        {
            Ok(Cursor::new(
                self.files
                    .lock()
                    .await
                    .get(path.as_ref())
                    .unwrap()
                    .as_bytes()
                    .to_owned(),
            ))
        }

        async fn size<P>(&self, path: P) -> Result<u64, Box<dyn Error>>
        where
            P: AsRef<Path> + Send + Sync,
        {
            let size = self.files.lock().await.get(path.as_ref()).ok_or("")?.len() as u64;
            Ok(size)
        }
    }

    #[tokio::test]
    async fn should_return_starting_position_as_0_if_file_does_not_exist() {
        let fs = FakeFs::new();
        let args = vec!["", "logs"];
        let config = Opt::from_iter(args).handle(fs).await.unwrap();
        assert_eq!(0, config.start);
    }

    #[tokio::test]
    async fn should_return_starting_position_as_0_if_file_exists_but_is_empty() {
        let path = PathBuf::from("test");
        let mut existing = HashMap::new();
        existing.insert(path, "".to_owned());
        let fs = FakeFs::from_map(existing);
        let args = vec!["", "logs"];
        let config = Opt::from_iter(args).handle(fs).await.unwrap();
        assert_eq!(0, config.start)
    }

    #[tokio::test]
    async fn should_return_starting_position_as_max_position_if_file_exists_with_entries() {
        let path = PathBuf::from("logs");
        let mut existing = HashMap::new();
        let data = r#"{"x509": {"position":2, "issuer":[], "subject":[], "san":[], "cert":""}}
            {"pre_cert": {"position":4}}"#;
        existing.insert(path, data.to_owned());
        let fs = FakeFs::from_map(existing);
        let args = vec!["", "logs"];
        let config = Opt::from_iter(args).handle(fs).await.unwrap();
        assert_eq!(5, config.start)
    }

    #[tokio::test]
    async fn should_return_appendable_writer_if_file_exists_with_entries() {
        let path = PathBuf::from("logs");
        let mut existing = HashMap::new();
        let data = r#"{"x509":{"position":2, "issuer":[], "subject":[], "san":[], "cert":""}}"#;
        existing.insert(path, data.to_owned());
        let fs = FakeFs::from_map(existing);
        let args = vec!["", "logs"];
        let mut config = Opt::from_iter(args).handle(fs).await.unwrap();
        config.writer.write_all(b"test").await.unwrap();
        config.writer.flush();
    }
}
