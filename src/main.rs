use std::path::Path;
use std::io;
use positioned_io::{RandomAccessFile, ReadBytesAtExt as _};
use byteorder::LE;

#[derive(Debug)]
struct Database {
    raf: RandomAccessFile,
    info: DatabaseInfo,
}

#[derive(Debug)]
struct DatabaseInfo {
    px: u8,
    columns: u8,
    year: u8,
    month: u8,
    day: u8,
    rows: u32,
    base_addr: u32,
    rows_ipv6: u32,
    base_addr_ipv6: u32,
    index_base_addr: u32,
    index_base_addr_ipv6: u32,
}

impl Database {
    fn open<P: AsRef<Path>>(path: P) -> io::Result<Database> {
        let raf = RandomAccessFile::open(path)?;

        Ok(Database {
            info: DatabaseInfo {
                px: raf.read_u8_at(0)?,
                columns: raf.read_u8_at(1)?,
                year: raf.read_u8_at(2)?,
                month: raf.read_u8_at(3)?,
                day: raf.read_u8_at(4)?,
                rows: raf.read_u32_at::<LE>(5)?,
                base_addr: raf.read_u32_at::<LE>(9)?,
                rows_ipv6: raf.read_u32_at::<LE>(13)?,
                base_addr_ipv6: raf.read_u32_at::<LE>(17)?,
                index_base_addr: raf.read_u32_at::<LE>(21)?,
                index_base_addr_ipv6: raf.read_u32_at::<LE>(25)?,
            },
            raf
        })
    }
}

fn main() {
    let db = Database::open("IP2PROXY-IP-PROXYTYPE-COUNTRY.BIN").unwrap();
    dbg!(db);
}
