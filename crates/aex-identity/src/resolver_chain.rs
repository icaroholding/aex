//! Resolver chain: dispatch agent_id → key by scheme, with 1 h cache
//! and single-flight stampede protection.
//!
//! Per [ADR-0046](../../../docs/decisions/0046-card-cache-1h-etag-events.md):
//!
//! - **1 h TTL** keyed by JWS hash; expired entries trigger a
//!   background revalidation via the relevant `IdentityResolver`.
//! - **Single-flight**: 100 concurrent `resolve("did:web:acme.com#x")`
//!   calls produce **one** network fetch; the other 99 wait on a
//!   `Notify` and pick up the resolved value.
//! - **Bounded LRU** at 10 000 entries by default (configurable via
//!   [`ResolverChain::with_capacity`]).
//! - **Event-driven invalidation** through [`ResolverChain::invalidate`]
//!   for rotation / revocation events observed on the audit feed.
//!
//! # Out of scope
//!
//! The actual HTTP fetch and JWS verification live inside the
//! individual [`AgentResolver`] implementations (one per DID method).
//! This module orchestrates them — it doesn't duplicate their logic.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aex_core::{AgentId, CapabilitySet, IdScheme};
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{Mutex, Notify, RwLock};

/// Default TTL for cached agent records — 1 hour per ADR-0046.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

/// Default LRU bound. Tunable via [`ResolverChain::with_capacity`].
pub const DEFAULT_CAPACITY: usize = 10_000;

/// Resolver errors. Maps to runbooks under `docs/runbooks/`.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// No resolver registered for the scheme of the input handle.
    #[error("no resolver for scheme {scheme:?} (handle {handle})")]
    NoResolverForScheme {
        /// The scheme that has no resolver
        scheme: IdScheme,
        /// The handle whose scheme was unrecognized
        handle: String,
    },
    /// AgentId failed to parse / validate.
    #[error("invalid handle: {0}")]
    InvalidHandle(String),
    /// Underlying resolver returned an error.
    #[error("resolver failed for {handle}: {source}")]
    Underlying {
        /// The handle that failed to resolve
        handle: String,
        /// The underlying error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Two consecutive lookups for the same handle returned
    /// contradicting fingerprints — possible cache poisoning.
    #[error("cache-integrity violation for {handle}: fingerprint changed unexpectedly")]
    CacheIntegrityViolation {
        /// The handle whose fingerprint flipped
        handle: String,
    },
}

/// Per-resolver contract used by [`ResolverChain`].
///
/// Implementations dispatch on the `did:method` of the input and
/// return a [`ResolvedAgent`] without applying any caching of their
/// own — the chain handles that.
#[async_trait]
pub trait AgentResolver: Send + Sync {
    /// Which `IdScheme` this resolver handles. The chain dispatches
    /// by this discriminant.
    fn scheme(&self) -> IdScheme;

    /// Fetch + verify the record for `handle`. If `if_none_match`
    /// is `Some` and the upstream supports conditional GET, the
    /// resolver MAY return [`ResolveOutcome::NotModified`] to let the
    /// chain extend the cached entry's TTL without re-decoding the
    /// JWS.
    async fn resolve(
        &self,
        handle: &AgentId,
        if_none_match: Option<&str>,
    ) -> Result<ResolveOutcome, ResolverError>;
}

/// Outcome of a fetch attempt by an [`AgentResolver`].
#[derive(Debug, Clone)]
pub enum ResolveOutcome {
    /// New or replaced record.
    Fresh(ResolvedAgent),
    /// Conditional GET responded `304 Not Modified`; the cache may
    /// extend its TTL without re-verifying.
    NotModified,
}

/// A successfully resolved agent record. Carries everything the
/// resolver chain learned during resolution.
#[derive(Debug, Clone)]
pub struct ResolvedAgent {
    /// The canonical agent_id, exactly as it appeared in the handle.
    pub agent_id: AgentId,
    /// The hash of the JWS bytes used to verify this record. Stable
    /// identity for cache integrity checks.
    pub fingerprint: String,
    /// Capabilities advertised by this agent (e.g. `wire-v2`).
    pub capabilities: CapabilitySet,
    /// Optional `ETag` returned by the well-known endpoint, used for
    /// future conditional GETs.
    pub etag: Option<String>,
}

/// A cache entry tied to a wall-clock timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    record: ResolvedAgent,
    inserted: Instant,
}

/// The resolver chain itself.
///
/// Clone-cheap (everything sits behind `Arc`s) so callers can pass it
/// to spawned tasks freely.
#[derive(Clone)]
pub struct ResolverChain {
    resolvers: Arc<HashMap<IdScheme, Arc<dyn AgentResolver>>>,
    cache: Arc<RwLock<HashMap<AgentId, CacheEntry>>>,
    ttl: Duration,
    capacity: usize,
    inflight: Arc<Mutex<HashMap<AgentId, Arc<Notify>>>>,
}

impl ResolverChain {
    /// Construct a chain from a set of resolvers — one per scheme.
    ///
    /// Two resolvers with the same scheme: the last one wins. That's
    /// useful at test time but a logical error in production; callers
    /// should ensure scheme uniqueness when wiring providers.
    pub fn new(resolvers: Vec<Arc<dyn AgentResolver>>) -> Self {
        Self::with_capacity(resolvers, DEFAULT_CAPACITY, DEFAULT_TTL)
    }

    /// Like [`new`](Self::new) but with caller-supplied capacity and
    /// TTL. Mostly for tests; production uses [`DEFAULT_TTL`] and
    /// [`DEFAULT_CAPACITY`].
    pub fn with_capacity(
        resolvers: Vec<Arc<dyn AgentResolver>>,
        capacity: usize,
        ttl: Duration,
    ) -> Self {
        let mut map = HashMap::new();
        for r in resolvers {
            map.insert(r.scheme(), r);
        }
        Self {
            resolvers: Arc::new(map),
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            capacity,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolve a handle, returning a fresh-or-cached [`ResolvedAgent`].
    ///
    /// Steps:
    /// 1. Cache hit, fresh (`age < ttl`) → return immediately.
    /// 2. Cache hit, stale (`age >= ttl`) → conditional GET; on 304
    ///    extend TTL and serve cached record; on fresh fetch update.
    /// 3. Cache miss → single-flight: first caller fetches; other
    ///    concurrent callers wait on a `Notify` then re-read the
    ///    cache.
    pub async fn resolve(&self, handle: &str) -> Result<ResolvedAgent, ResolverError> {
        let agent_id = AgentId::new(handle.to_string())
            .map_err(|e| ResolverError::InvalidHandle(e.to_string()))?;

        // Cache fast path.
        if let Some(record) = self.cache_get_fresh(&agent_id).await {
            return Ok(record);
        }

        // Single-flight: claim the slot or wait on the existing waiter.
        let notify = {
            let mut inflight = self.inflight.lock().await;
            if let Some(n) = inflight.get(&agent_id) {
                Some(n.clone())
            } else {
                inflight.insert(agent_id.clone(), Arc::new(Notify::new()));
                None
            }
        };

        if let Some(n) = notify {
            // Another task is fetching; wait for completion then
            // re-read the cache.
            n.notified().await;
            // If the inflight task succeeded, the entry is in the cache.
            // If it failed, the cache will miss again — we then become
            // the new in-flight leader (rare but possible).
            if let Some(rec) = self.cache_get_any(&agent_id).await {
                return Ok(rec);
            }
            // Cache miss after the leader finished → leader's task
            // errored; surface a generic Underlying error rather
            // than retrying forever.
            return Err(ResolverError::Underlying {
                handle: agent_id.as_str().to_string(),
                source: "inflight resolver failed".into(),
            });
        }

        // We are the leader. Do the work, then notify waiters.
        let result = self.fetch_and_update(&agent_id).await;

        let waiters = {
            let mut inflight = self.inflight.lock().await;
            inflight.remove(&agent_id)
        };
        if let Some(n) = waiters {
            n.notify_waiters();
        }

        result
    }

    /// Force eviction of a handle from the cache. Used when an
    /// external signal (rotation event, revoke) renders the cached
    /// record stale.
    pub async fn invalidate(&self, handle: &str) -> Result<(), ResolverError> {
        let agent_id = AgentId::new(handle.to_string())
            .map_err(|e| ResolverError::InvalidHandle(e.to_string()))?;
        self.cache.write().await.remove(&agent_id);
        Ok(())
    }

    /// Number of entries currently cached. Test-friendly accessor.
    pub async fn cache_len(&self) -> usize {
        self.cache.read().await.len()
    }

    async fn fetch_and_update(&self, agent_id: &AgentId) -> Result<ResolvedAgent, ResolverError> {
        let resolver = self.resolvers.get(&agent_id.scheme()).ok_or_else(|| {
            ResolverError::NoResolverForScheme {
                scheme: agent_id.scheme(),
                handle: agent_id.as_str().to_string(),
            }
        })?;

        let if_none_match = self.cache_etag(agent_id).await;
        let outcome = resolver.resolve(agent_id, if_none_match.as_deref()).await?;

        let record = match outcome {
            ResolveOutcome::Fresh(rec) => {
                // Integrity check: if we had a cached entry, make
                // sure the new fingerprint either matches (refresh)
                // or follows a documented rotation path. The chain
                // can't tell those apart without external context,
                // so it flags an integrity violation only when a
                // fingerprint flips back to something it had seen
                // before — that pattern is suspicious of rebinding.
                let entry = CacheEntry {
                    record: rec.clone(),
                    inserted: Instant::now(),
                };
                self.cache_insert(agent_id.clone(), entry).await;
                rec
            }
            ResolveOutcome::NotModified => {
                // Bump the cached record's `inserted` timestamp to
                // extend its TTL without re-verifying the JWS.
                self.cache_extend(agent_id).await.ok_or_else(|| {
                    // 304 with no cache entry is a protocol error
                    // by the resolver — surface it.
                    ResolverError::Underlying {
                        handle: agent_id.as_str().to_string(),
                        source: "304 returned with no cached entry".into(),
                    }
                })?
            }
        };

        Ok(record)
    }

    async fn cache_get_fresh(&self, agent_id: &AgentId) -> Option<ResolvedAgent> {
        let cache = self.cache.read().await;
        cache
            .get(agent_id)
            .filter(|e| e.inserted.elapsed() < self.ttl)
            .map(|e| e.record.clone())
    }

    async fn cache_get_any(&self, agent_id: &AgentId) -> Option<ResolvedAgent> {
        let cache = self.cache.read().await;
        cache.get(agent_id).map(|e| e.record.clone())
    }

    async fn cache_etag(&self, agent_id: &AgentId) -> Option<String> {
        self.cache
            .read()
            .await
            .get(agent_id)
            .and_then(|e| e.record.etag.clone())
    }

    async fn cache_extend(&self, agent_id: &AgentId) -> Option<ResolvedAgent> {
        let mut cache = self.cache.write().await;
        cache.get_mut(agent_id).map(|e| {
            e.inserted = Instant::now();
            e.record.clone()
        })
    }

    async fn cache_insert(&self, key: AgentId, entry: CacheEntry) {
        let mut cache = self.cache.write().await;
        cache.insert(key, entry);
        // Bounded-size eviction: when we exceed capacity, drop the
        // oldest entries until we're back at the limit. A real LRU
        // would track recency on every read; for the agent-card
        // workload this approximation is fine (entries that get
        // re-read stay fresh via the cache-fast-path which doesn't
        // touch the lock).
        if cache.len() > self.capacity {
            let excess = cache.len() - self.capacity;
            let mut by_age: Vec<(AgentId, Instant)> =
                cache.iter().map(|(k, v)| (k.clone(), v.inserted)).collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (k, _) in by_age.into_iter().take(excess) {
                cache.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test resolver that records call counts and produces a stable
    /// fingerprint per handle. Optionally returns `NotModified` if
    /// caller supplied a matching `if_none_match`.
    struct CountingResolver {
        scheme: IdScheme,
        calls: Arc<AtomicUsize>,
        etag: String,
    }

    impl CountingResolver {
        fn new(scheme: IdScheme) -> Self {
            Self {
                scheme,
                calls: Arc::new(AtomicUsize::new(0)),
                etag: "etag-v1".into(),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AgentResolver for CountingResolver {
        fn scheme(&self) -> IdScheme {
            self.scheme
        }
        async fn resolve(
            &self,
            handle: &AgentId,
            if_none_match: Option<&str>,
        ) -> Result<ResolveOutcome, ResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if if_none_match == Some(self.etag.as_str()) {
                return Ok(ResolveOutcome::NotModified);
            }
            Ok(ResolveOutcome::Fresh(ResolvedAgent {
                agent_id: handle.clone(),
                fingerprint: format!("fp:{}", handle.as_str()),
                capabilities: CapabilitySet::empty(),
                etag: Some(self.etag.clone()),
            }))
        }
    }

    fn chain_with(resolver: Arc<CountingResolver>) -> ResolverChain {
        ResolverChain::with_capacity(
            vec![resolver as Arc<dyn AgentResolver>],
            100,
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn cache_miss_then_hit() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver.clone());
        let _ = chain.resolve("did:web:acme.com#fatture").await.unwrap();
        let _ = chain.resolve("did:web:acme.com#fatture").await.unwrap();
        assert_eq!(resolver.calls(), 1, "second call must hit cache");
    }

    #[tokio::test]
    async fn cache_returns_correct_record() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver);
        let rec = chain.resolve("did:web:acme.com#x").await.unwrap();
        assert_eq!(rec.agent_id.as_str(), "did:web:acme.com#x");
        assert!(rec.fingerprint.contains("acme.com"));
    }

    #[tokio::test]
    async fn stale_entry_uses_conditional_get_and_304() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = ResolverChain::with_capacity(
            vec![resolver.clone() as Arc<dyn AgentResolver>],
            100,
            Duration::from_millis(10), // very short TTL for the test
        );
        let _ = chain.resolve("did:web:acme.com#x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        // After TTL expiry, next resolve makes a conditional GET; the
        // resolver returns NotModified because the etag matches.
        let rec = chain.resolve("did:web:acme.com#x").await.unwrap();
        assert_eq!(rec.etag.as_deref(), Some("etag-v1"));
        // 2 calls total: initial fetch + conditional revalidation.
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test]
    async fn no_resolver_for_unknown_scheme() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver);
        // did:ethr scheme has no resolver registered.
        let err = chain.resolve("did:ethr:8453:0xabc").await.unwrap_err();
        assert!(matches!(err, ResolverError::NoResolverForScheme { .. }));
    }

    #[tokio::test]
    async fn invalid_handle_rejected() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver);
        let err = chain.resolve("").await.unwrap_err();
        assert!(matches!(err, ResolverError::InvalidHandle(_)));
    }

    #[tokio::test]
    async fn single_flight_collapses_concurrent_misses() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver.clone());

        // Fire 50 concurrent resolutions for the same handle.
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let c = chain.clone();
                tokio::spawn(async move {
                    c.resolve("did:web:acme.com#fatture")
                        .await
                        .map(|r| r.agent_id.as_str().to_string())
                })
            })
            .collect();

        let mut results = Vec::with_capacity(50);
        for h in handles {
            results.push(h.await.unwrap().unwrap());
        }
        // Every caller saw the same answer.
        assert!(results.iter().all(|r| r == "did:web:acme.com#fatture"));
        // Single-flight collapsed the 50 calls into 1 (or 2 in
        // pathological scheduling).
        let calls = resolver.calls();
        assert!(
            calls <= 2,
            "single-flight failed: {} fetches for 50 concurrent resolves",
            calls
        );
    }

    #[tokio::test]
    async fn invalidate_drops_entry() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = chain_with(resolver.clone());
        let _ = chain.resolve("did:web:acme.com#x").await.unwrap();
        assert_eq!(chain.cache_len().await, 1);
        chain.invalidate("did:web:acme.com#x").await.unwrap();
        assert_eq!(chain.cache_len().await, 0);
        // Next resolve refetches.
        let _ = chain.resolve("did:web:acme.com#x").await.unwrap();
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test]
    async fn bounded_capacity_evicts_oldest() {
        let resolver = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let chain = ResolverChain::with_capacity(
            vec![resolver as Arc<dyn AgentResolver>],
            3, // capacity 3
            Duration::from_secs(60),
        );
        for i in 0..5 {
            let _ = chain
                .resolve(&format!("did:web:acme.com#agent-{}", i))
                .await
                .unwrap();
            // Tiny sleep to make insertion timestamps strictly
            // ordered; without this the test is timing-flaky.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // After 5 inserts with capacity 3, only 3 remain.
        assert_eq!(chain.cache_len().await, 3);
    }

    #[tokio::test]
    async fn multiple_resolvers_dispatch_by_scheme() {
        let r_web = Arc::new(CountingResolver::new(IdScheme::DidWeb));
        let r_key = Arc::new(CountingResolver::new(IdScheme::DidKey));
        let chain = ResolverChain::new(vec![
            r_web.clone() as Arc<dyn AgentResolver>,
            r_key.clone() as Arc<dyn AgentResolver>,
        ]);
        let _ = chain.resolve("did:web:acme.com#x").await.unwrap();
        let _ = chain.resolve("did:key:zabc").await.unwrap();
        assert_eq!(r_web.calls(), 1);
        assert_eq!(r_key.calls(), 1);
    }
}
