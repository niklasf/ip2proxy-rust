use std::path::Path;
use std::io;
use std::net::Ipv4Addr;
use positioned_io::{Cursor, RandomAccessFile, ReadBytesAtExt as _};
use byteorder::LE;
use byteorder::ReadBytesExt;

#[derive(Debug)]
struct Database {
    raf: RandomAccessFile,
    pub info: DatabaseInfo,
    index: Vec<OffsetRange>,
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

#[derive(Debug, Copy, Clone)]
struct OffsetRange {
    low: u32,
    high: u32,
}

const INDEX_SIZE: usize = 65536;

impl Database {
    fn open<P: AsRef<Path>>(path: P) -> io::Result<Database> {
        let raf = RandomAccessFile::open(path)?;

        let info = {
            let mut cursor = Cursor::new_pos(&raf, 0);
            DatabaseInfo {
                px: cursor.read_u8()?,
                columns: cursor.read_u8()?,
                year: cursor.read_u8()?,
                month: cursor.read_u8()?,
                day: cursor.read_u8()?,
                rows: cursor.read_u32::<LE>()?,
                base_addr: cursor.read_u32::<LE>()?,
                rows_ipv6: cursor.read_u32::<LE>()?,
                base_addr_ipv6: cursor.read_u32::<LE>()?,
                index_base_addr: cursor.read_u32::<LE>()?,
                index_base_addr_ipv6: cursor.read_u32::<LE>()?,
            }
        };

        let index = {
            let mut cursor = Cursor::new_pos(&raf, u64::from(info.index_base_addr) - 1);
            let mut index = Vec::with_capacity(INDEX_SIZE);
            while index.len() < INDEX_SIZE {
                index.push(OffsetRange {
                    low: cursor.read_u32::<LE>()?,
                    high: cursor.read_u32::<LE>()?,
                });
            }
            index
        };

        Ok(Database {
            raf,
            info,
            index,
        })
    }

    fn query_ipv4(&self, addr: Ipv4Addr) -> io::Result<()> {
        let base_addr = self.info.base_addr;
        let column_size = u32::from(self.info.columns) << 2;
        let ipnum = u32::from(addr);
        let indexaddr = ipnum >> 16;
        let OffsetRange { mut low, mut high } = self.index[indexaddr as usize];

        // TODO: check with max ip range?

        while (low <= high) {
            dbg!(ipnum, low, high);
            let mid = (low + high) / 2; // TODO: overflow
            let rowoffset = self.info.base_addr + mid * column_size;
            let rowoffset2 = rowoffset + column_size;

            let ipfrom = self.raf.read_u32_at::<LE>(u64::from(rowoffset) - 1)?;
            let ipto = self.raf.read_u32_at::<LE>(u64::from(rowoffset2) - 1)?;

            if ipfrom <= ipnum && ipnum < ipto {
                println!("found!");
                return Ok(());
            } else {
                if ipnum < ipfrom {
                    high = mid - 1; // overflow
                } else {
                    low = mid + 1; // overflow
                }
            }
        }

        Ok(())
    }
}

fn main() {
    let db = Database::open("IP2PROXY-IP-PROXYTYPE-COUNTRY.BIN").unwrap();
    dbg!(&db.info);
    db.query_ipv4("188.225.39.168".parse().unwrap());
}
