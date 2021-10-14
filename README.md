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

let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN")?;

assert_eq!(db.get_package_version(), 11);
assert_eq!(db.get_database_version(), "21.5.28");

let row = db.query("1.0.0.1".parse()?, Columns::all())?;

assert_eq!(row, Some(Row {
    proxy_type: Some(String::from("DCH")),
    country_short: Some(String::from("US")),
    country_long: Some(String::from("United States of America")),
    region: Some(String::from("California")),
    city: Some(String::from("Los Angeles")),
    isp: Some(String::from("APNIC and CloudFlare DNS Resolver Project")),
    domain: Some(String::from("cloudflare.com")),
    usage_type: Some(String::from("CDN")),
    asn: Some(String::from("13335")),
    as_name: Some(String::from("CloudFlare Inc")),
    last_seen: Some(String::from("27")),
    threat: Some(String::from("-")),
    provider: Some(String::from("-")),
    ..Row::default()
}));
```

Documentation
-------------

[Read the documentation](https://docs.rs/ip2proxy)

License
-------

This is an independently developed open-source library, licensed under the
MIT or Apache 2.0 license at your option. The author is not associated with
*IP2Location.com*.
