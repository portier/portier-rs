use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;
use url::Url;

use crate::misc::{DynErr, DynFut, DynFutRes};

/// Errors that can result from `Store::fetch`.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Store(DynErr),
    #[error(transparent)]
    Fetch(Arc<DynErr>),
}

/// Trait that describes a backing store used by `Client` for two purposes:
/// - to fetch JSON documents using HTTP GET with additional caching, and
/// - to generate and manage nonces (numbers used once) used in authentication.
///
/// The store is shared between threads by reference, and is itself responsible for synchronizing
/// access from different threads.
pub trait Store: Send + Sync + 'static {
    /// Requests a document using HTTP GET, and perform caching.
    ///
    /// Implementors should honor HTTP cache headers, with a sensibile minimum (and possibly
    /// maximum) applied to the cache lifespan. See `simple_fetch` for a default fallback
    /// implementation that can be used on cache miss.
    fn fetch(&self, url: Url) -> DynFut<Result<Bytes, FetchError>>;

    /// Generate a random nonce and store the pair nonce/email.
    ///
    /// See `generate_nonce` for a default implementation for generating the nonce, but using this
    /// is not required. When using a custom implementation, the returned string should be in some
    /// URL safe format to prevent unnecessary escaping.
    ///
    /// Implementors should not apply any limits to the amount of active nonces; this is left to
    /// the application using the `Client`.
    fn new_nonce(&self, email: String) -> DynFutRes<String>;

    /// Check that a nonce/email pair exists and delete it if so.
    ///
    /// This method should return `Ok(true)` if a pair was found, `Ok(false)` if not, and use `Err`
    /// only to indicate problems with the store.
    fn consume_nonce(&self, nonce: String, email: String) -> DynFutRes<bool>;
}

#[cfg(feature = "simple-store")]
mod simple;
#[cfg(feature = "simple-store")]
pub use simple::*;
