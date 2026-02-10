use sqlx::PgPool;

/// Create a PostgreSQL connection pool from the given database URL.
pub async fn create_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}
