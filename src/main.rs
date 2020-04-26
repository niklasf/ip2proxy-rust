#![forbid(unsafe_code)]

use std::path::Path;
use std::io;
use std::io::Read;
use std::net::Ipv4Addr;

use bitflags::bitflags;
use bstr::BString;
use byteorder::{LE, ReadBytesExt as _ };
use positioned_io::{Cursor, Slice, RandomAccessFile, ReadBytesAtExt as _, ReadAt as _};

bitflags! {
    pub struct Columns: u32 {
        const PROXY_TYPE    = 1 <<  0;
        const COUNTRY_SHORT = 1 <<  1;
        const COUNTRY_LONG  = 1 <<  2;
        const REGION        = 1 <<  3;
        const CITY          = 1 <<  4;
        const ISP           = 1 <<  5;
        const DOMAIN        = 1 <<  6;
        const USAGE_TYPE    = 1 <<  7;
        const ASN           = 1 <<  8;
        const AS_NAME       = 1 <<  9;
        const LAST_SEEN     = 1 << 10;

        const PX1 = Columns::COUNTRY_SHORT.bits | Columns::COUNTRY_LONG.bits;
        const PX2 = Columns::PROXY_TYPE.bits | Columns::PX1.bits;
        const PX3 = Columns::PX2.bits | Columns::REGION.bits | Columns::CITY.bits;
        const PX4 = Columns::PX3.bits | Columns::ISP.bits;
        const PX5 = Columns::PX4.bits | Columns::DOMAIN.bits;
        const PX6 = Columns::PX5.bits | Columns::USAGE_TYPE.bits;
        const PX7 = Columns::PX6.bits | Columns::ASN.bits | Columns::AS_NAME.bits;
        const PX8 = Columns::PX7.bits | Columns::LAST_SEEN.bits;
    }
}

#[derive(Debug, Default, Clone)]
pub struct Row {
    proxy_type: Option<BString>,
    country_short: Option<BString>,
    country_long: Option<BString>,
    region: Option<BString>,
    city: Option<BString>,
    isp: Option<BString>,
    domain: Option<BString>,
    usage_type: Option<BString>,
    asn: Option<BString>,
    as_name: Option<BString>,
    last_seen: Option<BString>,
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
pub struct Database {
    raf: RandomAccessFile,
    pub info: DatabaseInfo,
    index: Vec<OffsetRange>,
    columns: Columns,
}

#[derive(Debug)]
pub struct DatabaseInfo {
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

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Database> {
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
            columns: PX[usize::from(info.px)], // TODO: check
            raf,
            info,
            index,
        })
    }

    fn query_ipv4(&self, addr: Ipv4Addr) -> io::Result<Option<Row>> {
        let base_addr = self.info.base_addr;
        let column_size = u32::from(self.info.columns) << 2;
        let ipnum = u32::from(addr);
        let indexaddr = ipnum >> 16;
        let OffsetRange { mut low, mut high } = self.index[indexaddr as usize];

        // TODO: check with max ip range?

        while low <= high {
            dbg!(ipnum, low, high);
            let mid = (low + high) / 2; // TODO: overflow
            let rowoffset = self.info.base_addr + mid * column_size;
            let rowoffset2 = rowoffset + column_size;

            let ipfrom = self.raf.read_u32_at::<LE>(u64::from(rowoffset) - 1)?;
            let ipto = self.raf.read_u32_at::<LE>(u64::from(rowoffset2) - 1)?;

            if ipfrom <= ipnum && ipnum < ipto {
                let firstcol = 4; // ipv4
                return Ok(Some(self.read_row(rowoffset + firstcol - 1, column_size - firstcol, Columns::all())?)); // TODO: overflow
            } else {
                if ipnum < ipfrom {
                    high = mid - 1; // overflow
                } else {
                    low = mid + 1; // overflow
                }
            }
        }

        Ok(None)
    }

    fn read_row(&self, pos: u32, len: u32, query: Columns) -> io::Result<Row> {
        let mut buffer = vec![0; len as usize]; // TODO: allocation size
        self.raf.read_exact_at(u64::from(pos), &mut buffer)?;
        let mut cursor = io::Cursor::new(buffer);

        let mut row = Row::default();

        self.read_col(&mut cursor, query, &mut row.proxy_type, Columns::PROXY_TYPE);

        if self.columns.intersects(Columns::COUNTRY_SHORT | Columns::COUNTRY_LONG) {
            let offset = cursor.read_u32::<LE>()?;
            if query.contains(Columns::COUNTRY_SHORT) {
                row.country_short = Some(self.read_str(offset)?);
            }
            if query.contains(Columns::COUNTRY_LONG) {
                row.country_long = Some(self.read_str(offset + 3)?); // TODO: overflow
            }
        }

        self.read_col(&mut cursor, query, &mut row.region, Columns::REGION);
        self.read_col(&mut cursor, query, &mut row.city, Columns::CITY);
        self.read_col(&mut cursor, query, &mut row.isp, Columns::ISP);
        self.read_col(&mut cursor, query, &mut row.domain, Columns::DOMAIN);
        self.read_col(&mut cursor, query, &mut row.usage_type, Columns::USAGE_TYPE);
        self.read_col(&mut cursor, query, &mut row.asn, Columns::ASN);
        self.read_col(&mut cursor, query, &mut row.as_name, Columns::AS_NAME);
        self.read_col(&mut cursor, query, &mut row.last_seen, Columns::LAST_SEEN);

        Ok(row)
    }

    fn read_col<R: Read>(&self, mut reader: R, query: Columns, row: &mut Option<BString>, column: Columns) -> io::Result<()> {
        if self.columns.contains(column) {
            let ptr = reader.read_u32::<LE>()?;
            if query.contains(column) {
                *row = Some(self.read_str(ptr)?);
            }
        }
        Ok(())
    }

    fn read_str(&self, ptr: u32) -> io::Result<BString> {
        // +-----+-------+-------+-----+
        // | len | buf 0 | buf 1 | ... |
        // +-----+-------+-------+-----+
        let ptr = u64::from(ptr);
        let len = self.raf.read_u8_at(ptr)?;
        let mut buf = vec![0; usize::from(len)];
        self.raf.read_exact_at(ptr + 1, &mut buf)?;
        Ok(buf.into())
    }
}

fn main() {
    let db = Database::open("IP2PROXY-IP-PROXYTYPE-COUNTRY.BIN").unwrap();
    dbg!(&db.info);
    dbg!(db.query_ipv4("188.225.39.168".parse().unwrap()));
}
