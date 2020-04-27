use std::io;
use ip2proxy::{Database, Columns};
use bstr::BString;

#[test]
fn test_ipv4() {
    let database = Database::open("data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP.SAMPLE.BIN").unwrap();
    assert_eq!(database.header().px(), 4);
    assert_eq!(database.header().year(), 16);
    assert_eq!(database.header().month(), 11);
    assert_eq!(database.header().day(), 17);
    assert_eq!(database.header().rows_ipv4(), 150);
    assert_eq!(database.header().rows_ipv6(), 4);

    let ip = "1.0.0.1".parse().unwrap();
    let row = dbg!(database.query(ip, Columns::all()).unwrap().unwrap());
    assert_eq!(row.proxy_type, Some(BString::from("DCH")));
    assert_eq!(row.country_short, Some(BString::from("AU")));
    assert_eq!(row.country_long, Some(BString::from("Australia")));
    assert_eq!(row.region, Some(BString::from("Queensland")));
    assert_eq!(row.city, Some(BString::from("Brisbane")));
    assert_eq!(row.isp, Some(BString::from("Research Prefix for APNIC Labs")));
    assert!(row.domain.is_none());
    assert!(row.usage_type.is_none());
    assert!(row.asn.is_none());
    assert!(row.as_name.is_none());
    assert!(row.last_seen.is_none());

    let ip = "1.0.31.1".parse().unwrap();
    let row = dbg!(database.query(ip, Columns::all()).unwrap().unwrap());
    assert_eq!(row.proxy_type, Some(BString::from("DCH")));
    assert_eq!(row.country_short, Some(BString::from("JP")));
    assert_eq!(row.country_long, Some(BString::from("Japan")));
    assert_eq!(row.region, Some(BString::from("Tokyo")));
    assert_eq!(row.city, Some(BString::from("Tokyo")));
    assert_eq!(row.isp, Some(BString::from("I2TS Inc.")));
    assert!(row.domain.is_none());
    assert!(row.usage_type.is_none());
    assert!(row.asn.is_none());
    assert!(row.as_name.is_none());
    assert!(row.last_seen.is_none());
}
