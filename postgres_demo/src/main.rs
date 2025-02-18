use postgres::{Client, NoTls, Error};

fn main() -> Result<(), Error> {
    // 连接到数据库
    let mut client = Client::connect("postgresql://postgres:postgres@localhost/library", NoTls)?;

    // 创建 author 表
    client.batch_execute("
        CREATE TABLE IF NOT EXISTS author (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            country VARCHAR NOT NULL
        )
    ")?;

    // 创建 book 表
    client.batch_execute("
        CREATE TABLE IF NOT EXISTS book (
            id SERIAL PRIMARY KEY,
            title VARCHAR NOT NULL,
            author_id INTEGER NOT NULL REFERENCES author
        )
    ")?;

    // 插入数据
    client.execute(
        "INSERT INTO author (name, country) VALUES ($1, $2)",
        &[&"Chinua Achebe", &"Nigeria"],
    )?;
    client.execute(
        "INSERT INTO author (name, country) VALUES ($1, $2)",
        &[&"Rabindranath Tagore", &"India"],
    )?;

    // 查询数据
    for row in client.query("SELECT id, name, country FROM author", &[])? {
        let id: i32 = row.get(0);
        let name: String = row.get(1);
        let country: String = row.get(2);
        println!("id:{} Author {} is from {}", id, name, country);
    }

    Ok(())
}
