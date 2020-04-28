//! Library to query **IP2Proxy BIN Data** files. They contain known proxies,
//! geolocation information, and other meta data for IP address ranges.
//!
//! [https://www.ip2location.com/](https://www.ip2location.com/) is a
//! commercial provider, offering various database files for download.
//!
//! Supports IPv4 and IPv6.
//!
//! # Example
//!
//! ```rust
//! use ip2proxy::{Columns, Database, Row};
//!
//! let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;
//!
//! let row = db.query("1.0.0.1".parse()?, Columns::all())?;
//!
//! assert_eq!(row, Some(Row {
//!     proxy_type: Some(String::from("DCH")),
//!     country_short: Some(String::from("AU")),
//!     country_long: Some(String::from("Australia")),
//!     region: Some(String::from("Queensland")),
//!     city: Some(String::from("Brisbane")),
//!     isp: Some(String::from("Research Prefix for APNIC Labs")),
//!     ..Row::default()
//! }));
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! # Cargo features
//!
//! * `serde`: Implement `serde::Serialize` and `serde::Deserialize` for `Row`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::path::Path;
use std::io;
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::cmp::min;

use bitflags::bitflags;
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
        const PROXY_TYPE    = 1;
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

        /// See [`Row::is_proxy()`](struct.Row.html#method.is_proxy).
        const IS_PROXY = Columns::PROXY_TYPE.bits | Columns::COUNTRY_SHORT.bits;

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

/// Database record for an IP address.
///
/// Use [`Database::query()`](struct.Database.html#method.query) to obtain this
/// from a database.
///
/// By convention, `-` is used for fields where the column is supported but
/// the cell does not have a value.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Row {
    /// Type of proxy, if any.
    ///
    /// | Proxy type | Description |
    /// | --- | --- |
    /// | `VPN` | Anonymizing VPN service |
    /// | `TOR` | Tor exit node |
    /// | `DCH` | Data center, hosting provider, CDN |
    /// | `PUB` | Public proxy |
    /// | `WEB` | Web based proxy |
    /// | `SES` | Search engine spider |
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub proxy_type: Option<String>,

    /// ISO 3166 country code like `US`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub country_short: Option<String>,

    /// ISO 3166 country name like `United States of America`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub country_long: Option<String>,

    /// Region or state name like `California`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub region: Option<String>,

    /// City name like `Los Angeles`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub city: Option<String>,

    /// Internet service provider or company name, like
    /// `APNIC and CloudFlare DNS Resolver Project`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub isp: Option<String>,

    /// Domain name associated with the IP address, if any,
    /// like `cloudflare.com`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub domain: Option<String>,

    /// Usage type classification.
    ///
    /// | Usage type | Description |
    /// | --- | --- |
    /// | `COM` | Commercial |
    /// | `ORG` | Organization |
    /// | `GOV` | Government |
    /// | `MIL` | Military |
    /// | `EDU` | University, college, school |
    /// | `LIB` | Library |
    /// | `CDN` | Content Delivery Network |
    /// | `ISP` | Fixed Line ISP |
    /// | `MOB` | Mobile ISP |
    /// | `DCH` | Data center, hosting provider, transit |
    /// | `SES` | Search engine spider |
    /// | `RSV` | Reserved |
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub usage_type: Option<String>,

    /// Autonomous System Number (ASN), like `13335`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub asn: Option<String>,

    /// Autonomous System (AS) name, like `CLOUDFLARENET`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub as_name: Option<String>,

    /// Number of days since the proxy was last seen.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub last_seen: Option<String>,
}

impl Row {
    /// Checks if the row represents a known proxy of any kind.
    pub fn is_proxy(&self) -> Option<bool> {
        if let Some(ref country_short) = self.country_short {
            if country_short == "-" {
                return Some(false);
            }
        }
        if let Some(ref proxy_type) = self.proxy_type {
            return Some(proxy_type != "-");
        }
        None
    }
}

/// An IP2Proxy BIN database.
#[derive(Debug)]
pub struct Database {
    raf: RandomAccessFile,
    header: Header,
    index_v4: Option<IndexTable>,
    index_v6: Option<IndexTable>,
}

impl Database {
    /// Open a database file.
    ///
    /// # Example
    ///
    /// ```
    /// use ip2proxy::Database;
    ///
    /// let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// * Error while opening the file.
    /// * Error while reading from the file.
    /// * Invalid data in header section or index section.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::new(RandomAccessFile::open(path)?)
    }

    fn new(raf: RandomAccessFile) -> io::Result<Self> {
        let mut header_buf = [0; HEADER_LEN];
        raf.read_exact_at(0, &mut header_buf)?;
        let header = Header::read(&header_buf[..])?;

        Ok(Database {
            index_v4: if header.index_ptr_v4 != 0 {
                Some(IndexTable::read(Cursor::new_pos(&raf, u64::from(header.index_ptr_v4) - 1))?)
            } else {
                None
            },
            index_v6: if header.index_ptr_v6 != 0 {
                Some(IndexTable::read(Cursor::new_pos(&raf, u64::from(header.index_ptr_v6) - 1))?)
            } else {
                None
            },
            header,
            raf,
        })
    }

    /// Look up information for an IP address.
    ///
    /// The [`Columns`](struct.Columns.html) parameter allows optimizing the
    /// lookup by limiting the number columns to retrieve.
    ///
    /// Returns a [`Row`](struct.Row.html), if any.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ip2proxy::{Columns, Database, Row};
    ///
    /// let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;
    ///
    /// let row = db.query("1.0.0.1".parse()?, Columns::all())?;
    ///
    /// assert_eq!(row, Some(Row {
    ///     proxy_type: Some(String::from("DCH")),
    ///     country_short: Some(String::from("AU")),
    ///     country_long: Some(String::from("Australia")),
    ///     region: Some(String::from("Queensland")),
    ///     city: Some(String::from("Brisbane")),
    ///     isp: Some(String::from("Research Prefix for APNIC Labs")),
    ///     ..Row::default()
    /// }));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// * Error while reading from the source.
    /// * Invalid row or string data.
    pub fn query(&self, addr: IpAddr, query: Columns) -> io::Result<Option<Row>> {
        let addr = normalize_ip(addr);

        if let Some(RowRange { mut low_row, mut high_row }) = self.query_index(addr) {
            let (base_ptr, addr_size) = if addr.is_ipv4() {
                (self.header.base_ptr_v4, 4)
            } else {
                (self.header.base_ptr_v6, 16)
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
                        io::Error::new(ErrorKind::InvalidData, "underflow in binary search")
                    })?;
                } else if above {
                    low_row = mid_row.checked_add(1).ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "overflow in binary search")
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
        })
    }

    fn read_country_col<R: Read>(&self, mut reader: R, query: Columns) -> io::Result<(Option<String>, Option<String>)> {
        if self.header.columns.intersects(Columns::COUNTRY_SHORT | Columns::COUNTRY_LONG) {
            let ptr = u64::from(reader.read_u32::<LE>()?);
            let country_short = if query.contains(Columns::COUNTRY_SHORT) {
                Some(self.read_str(ptr)?)
            } else {
                None
            };
            let country_long = if query.contains(Columns::COUNTRY_LONG) {
                Some(self.read_str(ptr + 3)?) // ptr <= u32::MAX
            } else {
                None
            };
            Ok((country_short, country_long))
        } else {
            Ok((None, None))
        }
    }

    fn read_col<R: Read>(&self, mut reader: R, query: Columns, column: Columns) -> io::Result<Option<String>> {
        if self.header.columns.contains(column) {
            let ptr = u64::from(reader.read_u32::<LE>()?);
            if query.contains(column) {
                return Ok(Some(self.read_str(ptr)?));
            }
        }
        Ok(None)
    }

    fn read_str(&self, ptr: u64) -> io::Result<String> {
        // +-----+-------+-------+-----+
        // | len | buf 0 | buf 1 | ... |
        // +-----+-------+-------+-----+
        let len = self.raf.read_u8_at(ptr)?;
        let mut buf = vec![0; usize::from(len)];
        self.raf.read_exact_at(ptr + 1, &mut buf)?; // ptr <= u32::MAX + 3
        String::from_utf8(buf).map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid utf-8 data"))
    }

    fn query_index(&self, addr: IpAddr) -> Option<RowRange> {
        // Index has a row range for each possibe value of the upper 16 bits.
        match addr {
            IpAddr::V4(addr) => self.index_v4.as_ref().map(|i| i.table[(u32::from(addr) >> 16) as usize]),
            IpAddr::V6(addr) => self.index_v6.as_ref().map(|i| i.table[usize::from(addr.segments()[0])]),
        }
    }

    /// Get meta data from the database header.
    ///
    /// # Example
    ///
    /// ```
    /// use ip2proxy::Database;
    ///
    /// let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;
    /// let header = db.header();
    /// assert_eq!(header.px(), 4);
    /// assert_eq!(header.year(), 16); // 2016
    /// assert_eq!(header.month(), 11); // November
    /// assert_eq!(header.day(), 17); // 17th
    /// assert_eq!(header.rows_ipv4(), 150);
    /// assert_eq!(header.rows_ipv6(), 4);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn header(&self) -> &Header {
        &self.header
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
            if let Some(addr) = addr.to_ipv4() {
                IpAddr::V4(addr)
            } else if Ipv6Addr::from(FROM_6TO4) <= addr && addr <= Ipv6Addr::from(TO_6TO4) {
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

/// A database header with meta information.
///
/// See [`Database::header()`](struct.Database.html#method.header) for a usage
/// example.
#[derive(Debug, Clone)]
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
    columns: Columns,
}

impl Header {
    fn read<R: Read>(mut reader: R) -> io::Result<Header> {
        let px = reader.read_u8()?;
        let columns = PX.get(usize::from(px)).copied().unwrap_or_else(Columns::empty);
        if columns.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidData, "only px1 - px8 supported"));
        }

        Ok(Header {
            px,
            columns,
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

    /// Get database format. Supported databases are PX1 to PX8.
    pub fn px(&self) -> u8 {
        self.px
    }

    /// Get the database creation year. Convention is `16` for `2016`.
    pub fn year(&self) -> u8 {
        self.year
    }

    /// Get the database creation month. Convention is `1` for January.
    pub fn month(&self) -> u8 {
        self.month
    }

    /// Get the database creation day. Convention is `1` for the first day
    /// of the month.
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Get the number of rows for IPv4 addresses. Rows can cover a range,
    /// so there may be information for many more IP addresses.
    pub fn rows_ipv4(&self) -> u32 {
        self.rows_v4
    }

    /// Get the number of rows for IPv6 addresses. Rows can cover a range,
    /// so there may be information for many more IP addresses.
    pub fn rows_ipv6(&self) -> u32 {
        self.rows_v6
    }

    /// Get the set of supported columns.
    ///
    /// # Example
    ///
    /// ```
    /// use ip2proxy::{Columns, Database};
    ///
    /// let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;
    /// assert!(db.header().columns().contains(Columns::PROXY_TYPE));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn columns(&self) -> Columns {
        self.columns
    }
}

const HEADER_LEN: usize = 5 + 6 * 4;

const MAX_COLUMNS: usize = 11;

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

fn validate_columns(num_columns: u8) -> io::Result<u8> {
    if num_columns < 1 || MAX_COLUMNS < usize::from(num_columns) {
        Err(io::Error::new(ErrorKind::InvalidData, "invalid number of columns"))
    } else {
        Ok(num_columns)
    }
}

#[derive(Debug, Copy, Clone)]
struct RowRange {
    low_row: u32,
    high_row: u32,
}

#[derive(Debug)]
struct IndexTable {
    table: Vec<RowRange>,
}

impl IndexTable {
    fn read<R: Read>(mut reader: R) -> io::Result<IndexTable> {
        let mut table = Vec::with_capacity(1 << 16);
        while table.len() < (1 << 16) {
            table.push(RowRange {
                low_row: reader.read_u32::<LE>()?,
                high_row: reader.read_u32::<LE>()?,
            })
        }
        Ok(IndexTable { table })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teredo() {
        let ipv6 = "2001:0:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap();
        let ipv4: IpAddr = "192.0.2.45".parse().unwrap();
        assert_eq!(normalize_ip(ipv6), ipv4);
    }

    #[test]
    fn test_6to4() {
        let ipv6 = "2002:A0B:1621::".parse().unwrap();
        let ipv4: IpAddr = "10.11.22.33".parse().unwrap();
        assert_eq!(normalize_ip(ipv6), ipv4);
    }
}
