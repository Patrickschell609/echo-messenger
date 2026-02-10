use sqlx::PgPool;

/// Run database migrations against the given pool.
pub async fn run_migrations(pool: &PgPool) -> anyhow::Result<()> {
    tracing::info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
    tracing::info!("Migrations complete");
    Ok(())
}
