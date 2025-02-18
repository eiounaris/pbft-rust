use tokio_postgres::{Client, NoTls, Error, types::ToSql};

pub struct DbClient {
    client: Client,
}

impl DbClient {
    // 创建一个新的 DbClient 实例并连接到数据库
    pub async fn new(db_host: &str, db_port: &str, db_user: &str, db_password: &str, db_name: &str) -> Result<Self, Error> {
        let connection_string = format!(
            "host={} port={} user={} password={} dbname={}",
            db_host, db_port, db_user, db_password, db_name
        );

        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls).await?;

        // Spawn the connection task
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("连接错误: {}", e);
            }
        });

        Ok(DbClient { client })
    }

    // 执行任意的 SQL 语句
    pub async fn execute_query(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<(), Error> {
        self.client.execute(query, params).await?;
        Ok(())
    }

    // 执行查询操作并返回查询结果
    pub async fn fetch_all_rows(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<tokio_postgres::Row>, Error> {
        let rows = self.client.query(query, params).await?;
        Ok(rows)
    }

    // 根据ID查询单条记录
    pub async fn fetch_by_id(&self, id: i32) -> Result<Option<tokio_postgres::Row>, Error> {
        let query = "SELECT * FROM users WHERE id = $1";
        let params: &[&(dyn ToSql + Sync)] = &[&id];
        
        let rows = self.client.query(query, params).await?;

        // 返回第一行，如果有的话
        Ok(rows.into_iter().next())
    }

    // 根据ID范围查询记录
    pub async fn fetch_by_id_range(&self, start_id: i32, end_id: i32) -> Result<Vec<tokio_postgres::Row>, Error> {
        let query = "SELECT * FROM users WHERE id BETWEEN $1 AND $2";
        let params: &[&(dyn ToSql + Sync)] = &[&start_id, &end_id];

        let rows = self.client.query(query, params).await?;
        Ok(rows)
    }
}

