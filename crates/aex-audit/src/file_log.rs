//! File-backed [`AuditLog`]: append-only JSONL with a chain head cached in
//! memory for fast `append`/`current_head`.
//!
//! On startup, the existing file is replayed to rebuild in-memory state
//! (length, chain head). This is O(file size) at launch but constant-time
//! afterwards. Acceptable for dev tier; Postgres-backed impl is on the
//! Phase 2 roadmap for scale.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::{
    event::{Event, EventReceipt, StoredEvent},
    AuditError, AuditLog, AuditResult, GENESIS_HEAD,
};

#[derive(Debug)]
pub struct FileAuditLog {
    inner: Arc<Mutex<Inner>>,
    path: PathBuf,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("head", &self.head)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

struct Inner {
    file: File,
    head: String,
    len: u64,
}

impl FileAuditLog {
    /// Open (creating if necessary) the given path and rebuild state by
    /// replaying any existing rows.
    pub async fn open(path: impl Into<PathBuf>) -> AuditResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        // Replay existing file to find head + length. Use a read-only
        // handle for the replay so we don't seek the write handle around.
        let (head, len) = replay(&path).await?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { file, head, len })),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

async fn replay(path: &Path) -> AuditResult<(String, u64)> {
    if !path.exists() {
        return Ok((GENESIS_HEAD.to_string(), 0));
    }
    let file = File::open(path).await?;
    let mut lines = BufReader::new(file).lines();
    let mut head = GENESIS_HEAD.to_string();
    let mut len: u64 = 0;
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let stored: StoredEvent = serde_json::from_str(&line)?;
        if stored.prev_hash != head {
            return Err(AuditError::ChainBroken {
                position: len,
                expected: head,
                found: stored.prev_hash,
            });
        }
        stored.verify_hash()?;
        head = stored.this_hash;
        len += 1;
    }
    Ok((head, len))
}

#[async_trait]
impl AuditLog for FileAuditLog {
    async fn append(&self, event: Event) -> AuditResult<EventReceipt> {
        let mut guard = self.inner.lock().await;
        let timestamp = OffsetDateTime::now_utc();
        let prev_hash = guard.head.clone();
        let this_hash = event.compute_hash(timestamp, &prev_hash)?;
        let stored = StoredEvent {
            position: guard.len,
            event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
            timestamp,
            prev_hash,
            this_hash: this_hash.clone(),
            event,
        };

        let mut line = serde_json::to_vec(&stored)?;
        line.push(b'\n');
        guard.file.write_all(&line).await?;
        guard.file.flush().await?;

        guard.head = this_hash.clone();
        guard.len += 1;

        Ok(EventReceipt {
            event_id: stored.event_id,
            position: stored.position,
            timestamp,
            chain_head: this_hash,
        })
    }

    async fn current_head(&self) -> AuditResult<String> {
        Ok(self.inner.lock().await.head.clone())
    }

    async fn verify_chain(&self) -> AuditResult<()> {
        // Re-replay the file from disk — this catches on-disk tampering
        // even if our in-memory head looks fine.
        let (head, len) = replay(&self.path).await?;
        let guard = self.inner.lock().await;
        if head != guard.head || len != guard.len {
            return Err(AuditError::ChainBroken {
                position: len,
                expected: guard.head.clone(),
                found: head,
            });
        }
        Ok(())
    }

    async fn len(&self) -> AuditResult<u64> {
        Ok(self.inner.lock().await.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn fresh_file_has_genesis_head() {
        let dir = tmpdir();
        let log = FileAuditLog::open(dir.path().join("audit.jsonl"))
            .await
            .unwrap();
        assert_eq!(log.current_head().await.unwrap(), GENESIS_HEAD);
        assert_eq!(log.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn append_persists_across_reopen() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        {
            let log = FileAuditLog::open(&path).await.unwrap();
            for i in 0..5 {
                log.append(Event::new(
                    EventKind::TransferInitiated,
                    "",
                    format!("tx_{}", i),
                    serde_json::json!({"seq": i}),
                ))
                .await
                .unwrap();
            }
        }
        // Reopen and verify state is rebuilt.
        let log = FileAuditLog::open(&path).await.unwrap();
        assert_eq!(log.len().await.unwrap(), 5);
        log.verify_chain().await.unwrap();
    }

    #[tokio::test]
    async fn tampered_file_rejected_on_reopen() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        {
            let log = FileAuditLog::open(&path).await.unwrap();
            for i in 0..3 {
                log.append(Event::new(
                    EventKind::TransferInitiated,
                    "",
                    format!("tx_{}", i),
                    serde_json::json!({"seq": i}),
                ))
                .await
                .unwrap();
            }
        }
        // Corrupt the middle line.
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        // Flip one char in the middle JSON — parseable JSON but wrong hash.
        let tampered = lines[1].replacen("\"seq\":1", "\"seq\":99", 1);
        lines[1] = &tampered;
        let rewritten = lines.join("\n") + "\n";
        tokio::fs::write(&path, rewritten).await.unwrap();

        let err = FileAuditLog::open(&path).await.unwrap_err();
        assert!(matches!(err, AuditError::HashMismatch { position: 1, .. }));
    }

    #[tokio::test]
    async fn empty_lines_skipped() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        {
            let log = FileAuditLog::open(&path).await.unwrap();
            log.append(Event::new(
                EventKind::AgentRegistered,
                "",
                "",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        }
        // Add a blank line at EOF.
        tokio::fs::write(
            &path,
            tokio::fs::read_to_string(&path).await.unwrap() + "\n\n",
        )
        .await
        .unwrap();
        let log = FileAuditLog::open(&path).await.unwrap();
        assert_eq!(log.len().await.unwrap(), 1);
    }
}
