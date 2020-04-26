use std::io;
use ip2proxy::Database;

#[test]
fn test_ipv4() -> io::Result<()> {
    let database = Database::open("data/IP2PROXY-LITE-PX8.BIN")?;
    let ip = "8.8.8.8".parse().unwrap();
    let row = dbg!(database.query_ipv4(ip)?.unwrap());
    Ok(())
}
