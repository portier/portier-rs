use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    error::Error as StdError,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use bytes::{BufMut, Bytes, BytesMut};
use hyper::{
    body::HttpBody, client::HttpConnector, header::HeaderName, service::Service, Body, StatusCode,
};
use hyper_tls::HttpsConnector;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex;
use url::Url;

use crate::misc::{base64url, DynErr, DynFut, DynFutRes};
use crate::{FetchError, Store};

type Request = hyper::Request<Body>;
type Response = hyper::Response<Body>;
type Client = hyper::Client<HttpsConnector<HttpConnector>>;

/// A `Store` implementation that keeps everything in-memory.
///
/// This is the default `Store` implementation if a `Client` is used without explicitely
/// configuring one.
///
/// Note that the cache in this store only grows. For clients that only talk to a trusted broker
/// (the default), this is fine, because it can be assumed only a couple of URLs are fetched
/// periodically.
///
/// This store will only function correctly if the application is a single process. When running
/// multiple workers, the different processes will not be able to recognize eachothers' sessions.
///
/// Restarting the application process will also cause a complete loss of all sessions. For low
/// traffic sites, this may be fine, because sessions are short-lived.
pub struct MemoryStore<C> {
    client: C,
    timeout: Duration,
    rng: SystemRandom,
    // Putting a lock on each item is probably not very efficient, but this is designed for usage
    // from a Relying Party with a single trusted Broker, so will likely only contain two entries:
    // the discovery document and the keys document.
    cache: StdMutex<HashMap<Url, Arc<TokioMutex<CacheItem>>>>,
    nonces: Arc<StdMutex<HashSet<(String, String)>>>,
}

impl<C> MemoryStore<C> {
    /// Create a store with a custom HTTP client configuration.
    ///
    /// If defaults are fine, use the `Default` implementation instead.
    pub fn with_http_client(client: C, timeout: Duration) -> Self {
        // Dummy RNG call to flush out any latency from lazy init.
        let rng = SystemRandom::new();
        let mut dummy = vec![8];
        rng.fill(&mut dummy)
            .expect("secure random number generator failed");

        MemoryStore {
            client,
            timeout,
            rng,
            cache: Default::default(),
            nonces: Default::default(),
        }
    }
}

impl Default for MemoryStore<Client> {
    /// Create a store with a default configuration.
    ///
    /// This create a Hyper client that uses `native-tls` for secure connections, and configures a
    /// timeout of 30-seconds for each request.
    fn default() -> Self {
        let client = hyper::Client::builder().build(HttpsConnector::new());
        Self::with_http_client(client, Duration::from_secs(30))
    }
}

impl<C> Store for MemoryStore<C>
where
    C: Service<Request, Response = Response> + Clone + Send + Sync + 'static,
    C::Error: StdError + Send + Sync + 'static,
    C::Future: Send,
{
    fn fetch(&self, url: Url) -> DynFut<Result<Bytes, FetchError>> {
        let client = self.client.clone();
        let timeout = self.timeout;
        let item = self
            .cache
            .lock()
            .unwrap()
            .entry(url.clone())
            .or_default()
            .clone();
        Box::pin(async move {
            let mut item = item.lock().await;
            if Instant::now() >= item.expires {
                let (result, max_age) = simple_fetch(client, timeout, url).await;
                item.result = result.map_err(Arc::new);
                item.expires = Instant::now() + max_age;
            }
            item.result.clone().map_err(FetchError::Fetch)
        })
    }

    fn new_nonce(&self, email: String) -> DynFutRes<String> {
        let rng = self.rng.clone();
        let nonces = self.nonces.clone();
        Box::pin(async move {
            let nonce = generate_nonce(rng).await;
            nonces.lock().unwrap().insert((nonce.clone(), email));
            Ok(nonce)
        })
    }

    fn consume_nonce(&self, nonce: String, email: String) -> DynFutRes<bool> {
        let res = self.nonces.lock().unwrap().remove(&(nonce, email));
        Box::pin(async move { Ok(res) })
    }
}

struct CacheItem {
    result: Result<Bytes, Arc<DynErr>>,
    expires: Instant,
}

impl Default for CacheItem {
    fn default() -> Self {
        CacheItem {
            result: Ok(Bytes::default()),
            expires: Instant::now(),
        }
    }
}

#[derive(Debug, Error)]
#[error("unexpected HTTP status code {0}")]
struct FetchStatusError(pub StatusCode);

/// Performs a simple GET-request using the given HTTP client, and handles the response.
///
/// This checks the response status, parses the `Cache-Control` header, and reads the response
/// body. The returned tuple has the max cache duration as the second element.
///
/// This is a default implementation for use by `Store::fetch` on cache miss.
pub async fn simple_fetch<C>(
    mut client: C,
    timeout: Duration,
    url: Url,
) -> (Result<Bytes, DynErr>, Duration)
where
    C: Service<Request, Response = Response>,
    C::Error: StdError + Send + Sync + 'static,
{
    // Error-case default cache lifespan.
    let mut max_age = Duration::from_secs(3);

    let (response, data) = match tokio::time::timeout(timeout, async {
        let request = hyper::Request::builder()
            .uri(hyper::Uri::try_from(String::from(url)).unwrap())
            .body(Body::empty())
            .unwrap();
        let mut response = match client.call(request).await {
            Ok(response) => response,
            Err(err) => return Err(Box::new(err) as DynErr),
        };

        if response.status() != 200 {
            let err = FetchStatusError(response.status());
            return Err(Box::new(err) as DynErr);
        }

        let size: usize = response
            .headers()
            .get(HeaderName::from_static("cache-control"))
            .and_then(|val| val.to_str().ok())
            .and_then(|val| val.parse().ok())
            .unwrap_or_default();

        let mut data = BytesMut::with_capacity(size);
        let body = response.body_mut();
        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(chunk) => data.put(chunk),
                Err(err) => return Err(Box::new(err) as DynErr),
            }
        }

        Ok((response, data))
    })
    .await
    {
        Ok(Ok(res)) => res,
        Ok(Err(err)) => return (Err(err), max_age),
        Err(err) => return (Err(Box::new(err)), max_age),
    };

    // Success-case default and minimum cache lifespan.
    max_age = Duration::from_secs(60);

    if let Some(val) = response
        .headers()
        .get(HeaderName::from_static("cache-control"))
        .and_then(|val| val.to_str().ok())
        .and_then(|val| {
            val.split(',')
                .find_map(|s| s.trim().strip_prefix("max-age="))
        })
        .and_then(|val| val.parse().ok())
    {
        max_age = max_age.max(Duration::from_secs(val));
    }

    (Ok(data.into()), max_age)
}

/// Returns 128-bits of secure random data in an URL-safe encoding.
///
/// This is a default implementation for use by `Store::new_nonce` to generate nonces (numbers used
/// once). This function panics if the RNG fails.
///
/// The RNG is usually `SystemRandom`. Note that `SystemRandom` may perform lazy initialization,
/// and it is therefore recommended to do a dummy `SystemRandom::fill` after creating. See
/// `SystemRandom::new` for details.
pub async fn generate_nonce(rng: impl SecureRandom + Send + Sync + 'static) -> String {
    tokio::task::spawn_blocking(move || {
        let mut data = vec![0; 16];
        rng.fill(&mut data[..])
            .expect("secure random number generator failed");
        base64url::encode(&data)
    })
    .await
    .expect("rng task panicked")
}
