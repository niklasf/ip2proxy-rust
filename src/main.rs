use std::path::Path;
use std::io;
use std::net::Ipv4Addr;
use positioned_io::{Cursor, Slice, RandomAccessFile, ReadBytesAtExt as _, ReadAt as _};
use byteorder::LE;
use byteorder::ReadBytesExt;
use bstr::BString;
use bitflags::bitflags;

bitflags! {
    pub struct Columns: u32 {
        const PROXY_TYPE = 1 << 0;
        const COUNTRY    = 1 << 1;
        const REGION     = 1 << 2;
        const CITY       = 1 << 3;
        const ISP        = 1 << 4;
        const DOMAIN     = 1 << 5;
        const USAGE_TYPE = 1 << 6;
        const ASN        = 1 << 7;
        const AS         = 1 << 8;
        const LAST_SEEN  = 1 << 9;

        const PX1 = Columns::COUNTRY.bits;
        const PX2 = Columns::PROXY_TYPE.bits | Columns::COUNTRY.bits;
        const PX3 = Columns::PX2.bits | Columns::REGION.bits | Columns::CITY.bits;
        const PX4 = Columns::PX3.bits | Columns::ISP.bits;
        const PX5 = Columns::PX4.bits | Columns::DOMAIN.bits;
        const PX6 = Columns::PX5.bits | Columns::USAGE_TYPE.bits;
        const PX7 = Columns::PX6.bits | Columns::ASN.bits | Columns::AS.bits;
        const PX8 = Columns::PX7.bits | Columns::LAST_SEEN.bits;
    }
}

const PX: [Columns; 9] = [
    Columns::empty(),
    Columns::PX1,
    Columns::PX2,
    Columns::PX3,
    Columns::PX4,
    Columns::PX5,
    Columns::PX6,
    Columns::PX7,
    Columns::PX8,
];

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

const PROXYTYPE_POS: [u64; 9] = [0, 0, 2, 2, 2, 2, 2, 2, 2];

struct QueryResult {
    proxy_type: u32,
}

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

                let firstcol = 4; // ipv4
                let row = Slice::new(&self.raf, u64::from(rowoffset + firstcol - 1), Some(u64::from(column_size - firstcol))); // TODO: overflow

                let proxytype_pos_offset = (PROXYTYPE_POS[usize::from(self.info.px)] - 2) << 2;

                let offset = row.read_u32_at::<LE>(proxytype_pos_offset)?;
                dbg!(offset);
                dbg!(self.read_str(offset));


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

    fn read_str(&self, pos: u32) -> io::Result<BString> {
        let pos = u64::from(pos);
        let len = self.raf.read_u8_at(pos)?;
        let mut buf = vec![0; usize::from(len)];
        self.raf.read_exact_at(pos + 1, &mut buf)?;
        Ok(buf.into())
    }
}

fn main() {
    let db = Database::open("IP2PROXY-IP-PROXYTYPE-COUNTRY.BIN").unwrap();
    dbg!(&db.info);
    db.query_ipv4("188.225.39.168".parse().unwrap());
}
