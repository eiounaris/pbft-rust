use super::db::DbClient;
use tokio_postgres::Error;
use dotenv::dotenv;
use std::env;

pub async fn connect_to_db() -> Result<DbClient, Error> {
    // 加载环境变量
    dotenv().ok();

    // 从环境变量中获取数据库连接信息
    let db_host = env::var("DB_HOST").expect("DB_HOST not set");
    let db_port = env::var("DB_PORT").expect("DB_PORT not set");
    let db_user = env::var("DB_USER").expect("DB_USER not set");
    let db_password = env::var("DB_PASSWORD").expect("DB_PASSWORD not set");
    let db_name = env::var("DB_NAME").expect("DB_NAME not set");

    Ok(DbClient::new(&db_host, &db_port, &db_user, &db_password, &db_name).await?)
}