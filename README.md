IP2Proxy Rust Library
=====================

[![Test](https://github.com/niklasf/ip2proxy-rust/workflows/Test/badge.svg)](https://github.com/niklasf/ip2proxy-rust/actions)
[![crates.io](https://img.shields.io/crates/v/ip2proxy.svg)](https://crates.io/crates/ip2proxy)
[![docs.rs](https://docs.rs/ip2proxy/badge.svg)](https://docs.rs/ip2proxy)

Library to query **IP2Proxy BIN Data** files. They contain known proxies,
geolocation information, and other meta data for IP address ranges.

https://www.ip2location.com/ is a commercial provider, offering various database
files for download.

Supports IPv4 and IPv6.

Usage example
-------------

```rust
use ip2proxy::{Columns, Database, Row};

let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;

let row = db.query("1.0.0.1".parse()?, Columns::all())?;

assert_eq!(row, Some(Row {
    proxy_type: Some(String::from("DCH")),
    country_short: Some(String::from("AU")),
    country_long: Some(String::from("Australia")),
    region: Some(String::from("Queensland")),
    city: Some(String::from("Brisbane")),
    isp: Some(String::from("Research Prefix for APNIC Labs")),
    ..Row::default()
}));
```

Documentation
-------------

[Read the documentation](https://docs.rs/ip2proxy)

License
-------

This is an independently developed open-source library, licensed under the
MIT or Apache-2.0 license at your option. The author is not associated with
*IP2Location.com*.
