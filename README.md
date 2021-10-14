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

assert_eq!(db.package_version(), 11);
assert_eq!(db.database_version(), "21.5.28");

if let Some(row) = db.query("1.0.0.1".parse()?, Columns::all())? {
    assert_eq!(row.proxy_type, Some(String::from("DCH")));
    assert_eq!(row.country_short, Some(String::from("US")));
    assert_eq!(row.country_long, Some(String::from("United States of America")));
    assert_eq!(row.region, Some(String::from("California")));
    assert_eq!(row.city, Some(String::from("Los Angeles")));
    assert_eq!(row.isp, Some(String::from("APNIC and CloudFlare DNS Resolver Project")));
    assert_eq!(row.domain, Some(String::from("cloudflare.com")));
    assert_eq!(row.usage_type, Some(String::from("CDN")));
    assert_eq!(row.asn, Some(String::from("13335")));
    assert_eq!(row.as_name, Some(String::from("CloudFlare Inc")));
    assert_eq!(row.last_seen, Some(String::from("27")));
    assert_eq!(row.threat, Some(String::from("-")));
    assert_eq!(row.provider, Some(String::from("-")));
}
```

Documentation
-------------

[Read the documentation](https://docs.rs/ip2proxy)

License
-------

This is an independently developed open-source library, licensed under the
MIT or Apache 2.0 license at your option. The author is not associated with
*IP2Location.com*.
