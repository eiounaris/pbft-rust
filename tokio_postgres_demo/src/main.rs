// main.rs
use tokio_postgres_demo::utils::connect_to_db;


#[tokio::main]
async fn main() {
    // 从环境变量中读取数据库配置
    let db_client = match connect_to_db().await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("数据库连接失败: {}", e);
            return;
        }
    };

    // 创建表的 SQL 语句
    let create_table_query = "
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        )
    ";

    // 执行创建表操作
    if let Err(e) = db_client.execute_query(create_table_query, &[]).await {
        eprintln!("创建表失败: {}", e);
        return;
    }

    // 插入用户的 SQL 语句
    let insert_user_query = "INSERT INTO users (name) VALUES ($1)";

    if let Err(e) = db_client.execute_query(insert_user_query, &[&"Alice"]).await {
        eprintln!("插入用户失败: {}", e);
        return;
    }

    // 查询用户的 SQL 语句
    let fetch_users_query = "SELECT id, name FROM users";

    match db_client.fetch_all_rows(fetch_users_query, &[]).await {
        Ok(rows) => {
            for row in rows {
                let id: i32 = row.get(0);
                let name: &str = row.get(1);
                println!("ID: {}, Name: {}", id, name);
            }
        }
        Err(e) => {
            eprintln!("查询用户失败: {}", e);
        }
    }

    // 根据ID查询用户
    match db_client.fetch_by_id(1).await {
        Ok(Some(row)) => {
            let id: i32 = row.get(0);
            let name: &str = row.get(1);
            println!("ID: {}, Name: {}", id, name);
        }
        Ok(None) => {
            println!("未找到用户");
        }
        Err(e) => {
            eprintln!("查询用户失败: {}", e);
        }
    }

    // 根据ID范围查询用户
    match db_client.fetch_by_id_range(1, 3).await {
        Ok(rows) => {
            for row in rows {
                let id: i32 = row.get(0);
                let name: &str = row.get(1);
                println!("ID: {}, Name: {}", id, name);
            }
        }
        Err(e) => {
            eprintln!("查询用户失败: {}", e);
        }
    }
}
