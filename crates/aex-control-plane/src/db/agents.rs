//! Database access layer for the `agents` and `registration_nonces` tables.
//!
//! Uses runtime (non-macro) sqlx queries so compilation doesn't require a
//! live database. We trade compile-time type checking for CI simplicity at
//! this stage — worth revisiting once the schema stabilizes.

use sqlx::PgPool;
use time::OffsetDateTime;

/// Row as stored in the `agents` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRow {
    pub id: uuid::Uuid,
    pub agent_id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub org: String,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Insert a freshly-verified agent row. Returns the inserted row.
///
/// Errors:
/// - `sqlx::Error::Database` with unique-violation constraint name — caller
///   maps to 409 Conflict. We surface the *field* that collided via
///   [`UniqueCollision`] so the handler can produce a useful message.
pub async fn insert(
    pool: &PgPool,
    agent_id: &str,
    public_key: &[u8],
    fingerprint: &str,
    org: &str,
    name: &str,
) -> Result<AgentRow, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentRow>(
        r#"
        INSERT INTO agents (agent_id, public_key, fingerprint, org, name)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, agent_id, public_key, fingerprint, org, name, created_at, revoked_at
        "#,
    )
    .bind(agent_id)
    .bind(public_key)
    .bind(fingerprint)
    .bind(org)
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn find_by_agent_id(
    pool: &PgPool,
    agent_id: &str,
) -> Result<Option<AgentRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentRow>(
        r#"
        SELECT id, agent_id, public_key, fingerprint, org, name, created_at, revoked_at
        FROM agents
        WHERE agent_id = $1
        "#,
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record that a nonce has been consumed. Returns `Ok(true)` on successful
/// insert, `Ok(false)` if the nonce was already present (replay).
pub async fn consume_nonce(
    pool: &PgPool,
    nonce: &str,
    public_key: &[u8],
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO registration_nonces (nonce, public_key)
        VALUES ($1, $2)
        ON CONFLICT (nonce) DO NOTHING
        "#,
    )
    .bind(nonce)
    .bind(public_key)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Classify a unique-violation error by constraint name.
pub fn unique_violation_field(err: &sqlx::Error) -> Option<&'static str> {
    let db_err = err.as_database_error()?;
    if db_err.code().as_deref() != Some("23505") {
        return None;
    }
    match db_err.constraint() {
        Some("agents_agent_id_key") => Some("agent_id"),
        Some("agents_public_key_key") => Some("public_key"),
        _ => Some("unknown"),
    }
}
