use crate::client::Logs;
use csv::{Writer, WriterBuilder};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader},
    path::Path,
};

pub struct Store {
    writer: Writer<File>,
    count: usize,
}

impl Store {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .unwrap();

        // TODO this will be slow for large files, fix it when it's a problem
        let count = BufReader::new(&file).lines().count();
        let writer = WriterBuilder::new().from_writer(file);
        Self { writer, count }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn write_logs(&mut self, logs: Logs) -> Result<(), Box<dyn Error>> {
        for entry in logs.entries {
            self.writer.serialize(entry)?;
        }
        if self.count % 10000 == 0 {
            self.writer.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Store;
    use csv::Writer;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn count_should_return_count_of_rows() {
        let dir = tempdir().unwrap();
        let mut expected_file = PathBuf::from(dir.path().clone());
        expected_file.push("argon.csv");
        let mut writer = Writer::from_path(&expected_file).unwrap();
        writer.write_record(&["test"]).unwrap();
        writer.write_record(&["test"]).unwrap();
        writer.flush().unwrap();
        let csv = Store::new(&expected_file);
        assert_eq!(csv.count(), 2);
    }

    #[test]
    fn new_should_create_argon_csv_file_if_it_doesnt_exist() {
        let dir = tempdir().unwrap();
        let mut expected_file = PathBuf::from(dir.path().clone());
        expected_file.push("argon.csv");
        let _ = Store::new(&expected_file);
        assert!(
            std::path::Path::exists(&expected_file),
            "file {:?} does not exist",
            &expected_file
        );
    }
}
