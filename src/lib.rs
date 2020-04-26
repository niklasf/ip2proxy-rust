#![forbid(unsafe_code)]

use std::path::Path;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::cmp::min;

use bitflags::bitflags;
use bstr::BString;
use byteorder::{LE, ReadBytesExt as _, ByteOrder as _};
use positioned_io::{Cursor, RandomAccessFile, ReadBytesAtExt as _, ReadAt as _};

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

#[derive(Debug, Clone)]
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

pub struct Database {
    raf: RandomAccessFile,
    header: Header,
    index_v4: Option<Index>,
    index_v6: Option<Index>,
    columns: Columns,
}

struct Header {
    px: u8,
    num_columns: u8,
    year: u8,
    month: u8,
    day: u8,
    rows_v4: u32,
    base_ptr_v4: u32,
    rows_v6: u32,
    base_ptr_v6: u32,
    index_ptr_v4: u32,
    index_ptr_v6: u32,
}

const HEADER_LEN: usize = 5 * 1 + 6 * 4;

const MAX_COLUMNS: usize = 11;

fn validate_columns(num_columns: u8) -> io::Result<u8> {
    if num_columns < 1 || MAX_COLUMNS < usize::from(num_columns) {
        Err(io::Error::new(io::ErrorKind::InvalidData, "invalid number of columns"))
    } else {
        Ok(num_columns)
    }
}

impl Header {
    fn read<R: Read>(mut reader: R) -> io::Result<Header> {
        Ok(Header {
            px: reader.read_u8()?,
            num_columns: validate_columns(reader.read_u8()?)?,
            year: reader.read_u8()?,
            month: reader.read_u8()?,
            day: reader.read_u8()?,
            rows_v4: reader.read_u32::<LE>()?,
            base_ptr_v4: reader.read_u32::<LE>()?,
            rows_v6: reader.read_u32::<LE>()?,
            base_ptr_v6: reader.read_u32::<LE>()?,
            index_ptr_v4: reader.read_u32::<LE>()?,
            index_ptr_v6: reader.read_u32::<LE>()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
struct RowRange {
    low_row: u32,
    high_row: u32,
}

struct Index {
    table: Vec<RowRange>,
}

impl Index {
    fn read<R: Read>(mut reader: R) -> io::Result<Index> {
        let mut table = Vec::with_capacity(1 << 16);
        while table.len() < (1 << 16) {
            table.push(RowRange {
                low_row: reader.read_u32::<LE>()?,
                high_row: reader.read_u32::<LE>()?,
            })
        }
        Ok(Index { table })
    }
}

fn mid(low_row: u32, high_row: u32) -> u32 {
    ((u64::from(low_row) + u64::from(high_row)) / 2) as u32
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Database> {
        let raf = RandomAccessFile::open(path)?;

        let mut header_buf = [0; HEADER_LEN];
        raf.read_exact_at(0, &mut header_buf);
        let header = Header::read(&header_buf[..])?;

        let columns = PX.get(usize::from(header.px)).copied().unwrap_or(Columns::empty());
        if columns.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "only px1 - px8 supported"));
        }

        Ok(Database {
            columns,
            index_v4: match header.index_ptr_v4 != 0 {
                true => Some(Index::read(Cursor::new_pos(&raf, u64::from(header.index_ptr_v4) - 1))?),
                false => None,
            },
            index_v6: match header.index_ptr_v6 != 0 {
                true => Some(Index::read(Cursor::new_pos(&raf, u64::from(header.index_ptr_v6) - 1))?),
                false => None,
            },
            raf,
            header,
        })
    }

    pub fn query(&self, addr: IpAddr, query: Columns) -> io::Result<Option<Row>> {
        if let Some(RowRange { mut low_row, mut high_row }) = self.query_index(addr) {
            let (base_ptr, addr_size) = if addr.is_ipv4() {
                (self.header.base_ptr_v4, 4)
            } else {
                (self.header.base_ptr_v6, 16)
            };

            let row_size = addr_size + (usize::from(self.header.num_columns) - 1) * 4;

            let addr = match addr {
                IpAddr::V4(addr) => IpAddr::V4(min(addr, Ipv4Addr::from(u32::MAX - 1))),
                IpAddr::V6(addr) => IpAddr::V6(min(addr, Ipv6Addr::from(u128::MAX - 1))),
            };

            let mut buffer = [0; 16 + 16 + (MAX_COLUMNS - 1) * 4];

            while low_row <= high_row {
                dbg!(low_row, high_row);
                let mid_row = mid(low_row, high_row);

                // TODO: overflow
                let row_ptr = base_ptr + mid_row * row_size as u32;

                let buf = &mut buffer[..(row_size + addr_size) as usize];
                self.raf.read_exact_at(u64::from(row_ptr) - 1, buf)?; // TODO

                let below = match addr {
                    IpAddr::V4(addr) => addr < Ipv4Addr::from(LE::read_u32(buf)),
                    IpAddr::V6(addr) => addr < Ipv6Addr::from(LE::read_u128(buf)),
                };

                let above = match addr {
                    IpAddr::V4(addr) => addr >= Ipv4Addr::from(LE::read_u32(&buf[row_size..])),
                    IpAddr::V6(addr) => addr >= Ipv6Addr::from(LE::read_u128(&buf[row_size..])),
                };

                if below {
                    high_row = mid_row - 1; // overflow
                } else if above {
                    low_row = mid_row + 1; // overflow
                } else {
                    println!("found!");
                    return Ok(Some(self.read_row(&buf[addr_size..row_size], query)?));
                }
            }
        }

        Ok(None)
    }

    fn query_index(&self, addr: IpAddr) -> Option<RowRange> {
        match addr {
            IpAddr::V4(addr) => self.index_v4.as_ref().map(|i| i.table[(u32::from(addr) >> 16) as usize]),
            IpAddr::V6(addr) => self.index_v6.as_ref().map(|i| i.table[usize::from(addr.segments()[0])]),
        }
    }

    fn read_row(&self, buf: &[u8], query: Columns) -> io::Result<Row> {
        let mut cursor = io::Cursor::new(buf);

        let proxy_type = self.read_col(&mut cursor, query, Columns::PROXY_TYPE)?;
        let (country_short, country_long) = self.read_country_col(&mut cursor, query)?;

        Ok(Row {
            proxy_type,
            country_short,
            country_long,
            region: self.read_col(&mut cursor, query, Columns::REGION)?,
            city: self.read_col(&mut cursor, query, Columns::CITY)?,
            isp: self.read_col(&mut cursor, query, Columns::ISP)?,
            domain: self.read_col(&mut cursor, query, Columns::DOMAIN)?,
            usage_type: self.read_col(&mut cursor, query, Columns::USAGE_TYPE)?,
            asn: self.read_col(&mut cursor, query, Columns::ASN)?,
            as_name: self.read_col(&mut cursor, query, Columns::AS_NAME)?,
            last_seen: self.read_col(&mut cursor, query, Columns::LAST_SEEN)?,
        })
    }

    fn read_country_col<R: Read>(&self, mut reader: R, query: Columns) -> io::Result<(Option<BString>, Option<BString>)> {
        if self.columns.intersects(Columns::COUNTRY_SHORT | Columns::COUNTRY_LONG) {
            let ptr = u64::from(reader.read_u32::<LE>()?);
            let country_short = match query.contains(Columns::COUNTRY_SHORT) {
                true => Some(self.read_str(ptr)?),
                false => None,
            };
            let country_long = match query.contains(Columns::COUNTRY_LONG) {
                true => Some(self.read_str(ptr + 3)?), // ptr <= u32::MAX
                false => None,
            };
            Ok((country_short, country_long))
        } else {
            Ok((None, None))
        }
    }

    fn read_col<R: Read>(&self, mut reader: R, query: Columns, column: Columns) -> io::Result<Option<BString>> {
        if self.columns.contains(column) {
            let ptr = u64::from(reader.read_u32::<LE>()?);
            if query.contains(column) {
                return Ok(Some(self.read_str(ptr)?));
            }
        }
        Ok(None)
    }

    fn read_str(&self, ptr: u64) -> io::Result<BString> {
        // +-----+-------+-------+-----+
        // | len | buf 0 | buf 1 | ... |
        // +-----+-------+-------+-----+
        let len = self.raf.read_u8_at(ptr)?;
        let mut buf = vec![0; usize::from(len)];
        self.raf.read_exact_at(ptr + 1, &mut buf)?; // ptr <= u32::MAX + 3
        Ok(buf.into())
    }
}
