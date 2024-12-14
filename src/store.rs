use sqlx::{Pool, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use crate::account::Account;

pub struct DataStore {
    pool: Pool<Sqlite>,
}

impl DataStore {
    pub async fn setup(max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
          .max_connections(max_connections)
          .connect("sqlite::memory:").await?;

        sqlx::query("\
          CREATE TABLE accounts (\
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\
            username VARCHAR(255) UNIQUE NOT NULL,\
            password TEXT NOT NULL
          )"
        ).execute(&pool).await?;

        Ok(DataStore{ pool })
    }

    pub async fn insert_account(&self, username: &str, password: &str) -> Result<(), sqlx::Error> {
        sqlx::query(r#"INSERT INTO accounts (username, password) VALUES ($1, $2)"#)
          .bind(username)
          .bind(password)
          .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn select_account(&self, username: &str) -> Result<Account, sqlx::Error> {
        sqlx::query_as::<_, Account>(r#"SELECT username, password FROM accounts WHERE username = $1"#)
          .bind(username)
          .fetch_one(&self.pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_datastore() {
        let ds = DataStore::setup(1).await.unwrap();
        let username = "user";
        let password = "user";

        ds.insert_account(username, password).await.unwrap();
        let account = ds.select_account(username).await.unwrap();

        assert_eq!(account.username, username);
        assert_eq!(account.password, password);
    }

    #[tokio::test]
    async fn test_no_data() {
        let ds = DataStore::setup(1).await.unwrap();
        let username = "user";
        let account = ds.select_account(username).await;
        assert!(account.is_err());
    }
}
