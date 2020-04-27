// TODO:
// - Test v6
// - Clippy
// - Documentation
// - Test 6to4
// - Test teredo
// - Database constructors
// - Row accessors
// - Serde for row
// - Reduce allocations while reading row?
// - Fuzzing
// - CI

#![forbid(unsafe_code)]

use std::path::Path;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::cmp::min;

use bitflags::bitflags;
use bstr::BString;
use byteorder::{LE, ReadBytesExt as _, ByteOrder as _};
use positioned_io::{Cursor, RandomAccessFile, ReadAt, ReadBytesAtExt as _};

bitflags! {
    /// Set of supported or selected columns.
    ///
    /// # Example
    ///
    /// ```
    /// use ip2proxy::Columns;
    ///
    /// assert_eq!(Columns::PX2, Columns::PROXY_TYPE | Columns::COUNTRY_SHORT | Columns::COUNTRY_LONG);
    /// ```
    pub struct Columns: u32 {
        /// See [`Row::proxy_type`](struct.Row.html#structfield.proxy_type).
        const PROXY_TYPE    = 1 <<  0;
        /// See [`Row::country_short`](struct.Row.html#structfield.country_short).
        const COUNTRY_SHORT = 1 <<  1;
        /// See [`Row::country_long`](struct.Row.html#structfield.country_long).
        const COUNTRY_LONG  = 1 <<  2;
        /// See [`Row::region`](struct.Row.html#structfield.region).
        const REGION        = 1 <<  3;
        /// See [`Row::city`](struct.Row.html#structfield.city).
        const CITY          = 1 <<  4;
        /// See [`Row::isp`](struct.Row.html#structfield.isp).
        const ISP           = 1 <<  5;
        /// See [`Row::domain`](struct.Row.html#structfield.domain).
        const DOMAIN        = 1 <<  6;
        /// See [`Row::usage_type`](struct.Row.html#structfield.usage_type).
        const USAGE_TYPE    = 1 <<  7;
        /// See [`Row::asn`](struct.Row.html#structfield.asn).
        const ASN           = 1 <<  8;
        /// See [`Row::as_name`](struct.Row.html#structfield.as_name).
        const AS_NAME       = 1 <<  9;
        /// See [`Row::last_seen`](struct.Row.html#structfield.last_seen).
        const LAST_SEEN     = 1 << 10;

        /// Alias for columns of PX1: IP-Country Database.
        const PX1 = Columns::COUNTRY_SHORT.bits | Columns::COUNTRY_LONG.bits;
        /// Alias for columns of PX2: IP-ProxyType-Country Database.
        const PX2 = Columns::PROXY_TYPE.bits | Columns::PX1.bits;
        /// Alias for columns of PX3: IP-ProxyType-Country-Region-City Database.
        const PX3 = Columns::PX2.bits | Columns::REGION.bits | Columns::CITY.bits;
        /// Alias for columns of PX4: IP-ProxyType-Country-Region-City-ISP Database.
        const PX4 = Columns::PX3.bits | Columns::ISP.bits;
        /// Alias for columns of PX5: IP-ProxyType-Country-Region-City-ISP-Domain Database.
        const PX5 = Columns::PX4.bits | Columns::DOMAIN.bits;
        /// Alias for columns of PX6: IP-ProxyType-Country-Region-City-ISP-Domain-UsageType
        /// Database.
        const PX6 = Columns::PX5.bits | Columns::USAGE_TYPE.bits;
        /// Alias for columns of PX7: IP-ProxyType-Country-Region-City-ISP-Domain-UsageType-ASN
        /// Database.
        const PX7 = Columns::PX6.bits | Columns::ASN.bits | Columns::AS_NAME.bits;
        /// Alias for columns of PX8:
        /// IP-ProxyType-Country-Region-City-ISP-Domain-UsageType-ASN-LastSeen Database.
        const PX8 = Columns::PX7.bits | Columns::LAST_SEEN.bits;
    }
}

#[derive(Debug, Clone)]
pub struct Row {
    pub proxy_type: Option<BString>,
    pub country_short: Option<BString>,
    pub country_long: Option<BString>,
    pub region: Option<BString>,
    pub city: Option<BString>,
    pub isp: Option<BString>,
    pub domain: Option<BString>,
    pub usage_type: Option<BString>,
    pub asn: Option<BString>,
    pub as_name: Option<BString>,
    pub last_seen: Option<BString>,
    _priv: (),
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

pub struct Database<R> {
    raf: R,
    header: Header,
    index_v4: Option<Index>,
    index_v6: Option<Index>,
    columns: Columns,
}

impl<R> Database<R> {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn columns(&self) -> Columns {
        self.columns
    }

    fn query_index(&self, addr: IpAddr) -> Option<RowRange> {
        match addr {
            IpAddr::V4(addr) => self.index_v4.as_ref().map(|i| i.table[(u32::from(addr) >> 16) as usize]),
            IpAddr::V6(addr) => self.index_v6.as_ref().map(|i| i.table[usize::from(addr.segments()[0])]),
        }
    }
}

impl Database<RandomAccessFile> {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::new(RandomAccessFile::open(path)?)
    }
}

impl<R: ReadAt> Database<R> {
    pub fn new(raf: R) -> io::Result<Self> {
        let mut header_buf = [0; HEADER_LEN];
        raf.read_exact_at(0, &mut header_buf)?;
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
        let addr = normalize_ip(addr);

        if let Some(RowRange { mut low_row, mut high_row }) = self.query_index(addr) {
            let (base_ptr, addr_size) = match addr.is_ipv4() {
                true => (self.header.base_ptr_v4, 4),
                false => (self.header.base_ptr_v6, 16),
            };

            if base_ptr == 0 {
                return Ok(None);
            }

            let row_size = addr_size + (usize::from(self.header.num_columns) - 1) * 4;

            let addr = match addr {
                IpAddr::V4(addr) => IpAddr::V4(min(addr, Ipv4Addr::from(u32::MAX - 1))),
                IpAddr::V6(addr) => IpAddr::V6(min(addr, Ipv6Addr::from(u128::MAX - 1))),
            };

            let mut buffer = [0; 16 + 16 + (MAX_COLUMNS - 1) * 4];

            while low_row <= high_row {
                let mid_row = mid(low_row, high_row);

                let row_ptr = u64::from(base_ptr) + u64::from(mid_row) * row_size as u64 - 1; // base_ptr > 0, row_size small
                let buf = &mut buffer[..(row_size + addr_size) as usize];
                self.raf.read_exact_at(row_ptr, buf)?; // row

                let below = match addr {
                    IpAddr::V4(addr) => addr < Ipv4Addr::from(LE::read_u32(buf)),
                    IpAddr::V6(addr) => addr < Ipv6Addr::from(LE::read_u128(buf)),
                };

                let above = match addr {
                    IpAddr::V4(addr) => addr >= Ipv4Addr::from(LE::read_u32(&buf[row_size..])),
                    IpAddr::V6(addr) => addr >= Ipv6Addr::from(LE::read_u128(&buf[row_size..])),
                };

                if below {
                    high_row = mid_row.checked_sub(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "underflow in binary search")
                    })?;
                } else if above {
                    low_row = mid_row.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "overflow in binary search")
                    })?;
                } else {
                    return Ok(Some(self.read_row(&buf[addr_size..row_size], query)?));
                }
            }
        }

        Ok(None)
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
            _priv: (),
        })
    }

    fn read_country_col<S: Read>(&self, mut reader: S, query: Columns) -> io::Result<(Option<BString>, Option<BString>)> {
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

    fn read_col<S: Read>(&self, mut reader: S, query: Columns, column: Columns) -> io::Result<Option<BString>> {
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

const FROM_6TO4: u128   = 0x2002_0000_0000_0000_0000_0000_0000_0000;
const TO_6TO4: u128     = 0x2002_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
const FROM_TEREDO: u128 = 0x2001_0000_0000_0000_0000_0000_0000_0000;
const TO_TEREDO: u128   = 0x2001_0000_ffff_ffff_ffff_ffff_ffff_ffff;

fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(addr) => {
            if Ipv6Addr::from(FROM_6TO4) <= addr && addr <= Ipv6Addr::from(TO_6TO4) {
                IpAddr::V4(((u128::from(addr) >> 80) as u32).into())
            } else if Ipv6Addr::from(FROM_TEREDO) <= addr && addr <= Ipv6Addr::from(TO_TEREDO) {
                IpAddr::V4((!u128::from(addr) as u32).into())
            } else {
                IpAddr::V6(addr)
            }
        },
    }
}

fn mid(low_row: u32, high_row: u32) -> u32 {
    ((u64::from(low_row) + u64::from(high_row)) / 2) as u32
}

const HEADER_LEN: usize = 5 * 1 + 6 * 4;

pub struct Header {
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

    pub fn px(&self) -> u8 {
        self.px
    }

    pub fn year(&self) -> u8 {
        self.year
    }

    pub fn month(&self) -> u8 {
        self.month
    }

    pub fn day(&self) -> u8 {
        self.day
    }

    pub fn rows_ipv4(&self) -> u32 {
        self.rows_v4
    }

    pub fn rows_ipv6(&self) -> u32 {
        self.rows_v6
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
