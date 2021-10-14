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
use ip2proxy::{Columns, Database};

let db = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.SAMPLE.BIN").unwrap();

let package_version = db.get_package_version();
let database_version = db.get_database_version();
println!("Database Version: {}", database_version);
println!("Package Version: {}", package_version);

let row = db.query("1.0.0.1".parse().unwrap(), Columns::all()).unwrap();

println!("{:#?}", row);
```

Documentation
-------------

[Read the documentation](https://docs.rs/ip2proxy)

License
-------

This is an independently developed open-source library, licensed under the
MIT or Apache 2.0 license at your option. The author is not associated with
*IP2Location.com*.
