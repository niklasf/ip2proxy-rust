IP2Proxy Rust Library
=====================

[![Test](https://github.com/niklasf/ip2proxy/workflows/Test/badge.svg)](https://github.com/niklasf/ip2proxy/actions)
[![crates.io](https://img.shields.io/crates/v/ip2proxy.svg)](https://crates.io/crates/ip2proxy)
[![docs.rs](https://docs.rs/ip2proxy/badge.svg)](https://docs.rs/ip2proxy)

Library to query **IP2Proxy BIN Data** files. These files contain known
proxies, geolocation information, and other meta data.

https://www.ip2location.com/ is a commercial provider for these database files.

Usage example
-------------

```rust
use ip2proxy::{Columns, Database};

let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN")?;

let ip = "1.0.0.1".parse()?;
if let Some(row) = db.query(ip, Columns::all())? {
    // Record found.
    assert_eq!(row.proxy_type, Some(String::from("DCH")));
    assert_eq!(row.country_short, Some(String::from("AU")));
    assert_eq!(row.country_long, Some(String::from("Australia")));
    assert_eq!(row.region, Some(String::from("Queensland")));
    assert_eq!(row.city, Some(String::from("Brisbane")));
    assert_eq!(row.isp, Some(String::from("Research Prefix for APNIC Labs")));

    // The sample database does not have the following columns.
    assert!(row.domain.is_none());
    assert!(row.usage_type.is_none());
    assert!(row.asn.is_none());
    assert!(row.as_name.is_none());
    assert!(row.last_seen.is_none());
} else {
    unreachable!("Sample database is known to contain this ip");
}

let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse()?;
if let Some(row) = db.query(ip, Columns::all())? {
    // This address has a matching record, but all columns are set to `-`.
    assert_eq!(row.proxy_type, Some(String::from("-")));
    assert_eq!(row.country_short, Some(String::from("-")));
    assert_eq!(row.country_long, Some(String::from("-")));
} else {
    unreachable!("Sample database is known to contain this ip");
}
```

Documentation
-------------

[Read the documentation](https://docs.rs/ip2proxy)

Changelog
---------

* 0.1.0
  - Initial release.

License
-------

This is an independently developed open-source library, licensed under the
MIT or Apache-2.0 license at your option. The author is not associated with
IP2Location.com.
