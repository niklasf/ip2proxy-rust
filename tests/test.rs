use std::io;
use ip2proxy::{Database, Columns};

#[test]
fn test_ipv4() -> io::Result<()> {
    let database = Database::open("data/IP2PROXY-LITE-PX8.BIN")?;
    //dbg!(&database.info);

    //let ip = "8.8.8.8".parse().unwrap();
    //let ip = "127.0.0.1".parse().unwrap();

    let ip = "1.0.104.238".parse().unwrap();
    let row = dbg!(database.query(ip, Columns::all())?.unwrap());
    Ok(())
}
