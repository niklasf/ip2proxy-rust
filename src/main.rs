use std::path::Path;
use std::io;
use positioned_io::{RandomAccessFile, ReadBytesAtExt as _ };

#[derive(Debug)]
struct Database {
    raf: RandomAccessFile,
    info: DatabaseInfo,
}

#[derive(Debug)]
struct DatabaseInfo {
    db_type: u8,
}

impl Database {
    fn open<P: AsRef<Path>>(path: P) -> io::Result<Database> {
        let raf = RandomAccessFile::open(path)?;

        Ok(Database {
            info: DatabaseInfo {
                db_type: raf.read_u8_at(0)?,
            },
            raf
        })
    }
}

fn main() {
    let db = Database::open("IP2PROXY-IP-PROXYTYPE-COUNTRY.BIN").unwrap();
    dbg!(db);
}
