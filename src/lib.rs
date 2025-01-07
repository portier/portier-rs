//! A client for the Portier protocol.
//!
//! The primary interface of this package is the `Client`. Construct one using `Client::builder` or
//! `Client::new`. See also the short example using the Rocket framework in
//! [`example/src/main.rs`](https://github.com/portier/portier-rs/blob/main/example/src/main.rs).
//!
//! Some data storage is needed to implement the protocol. This is used for tracking short-lived
//! login sessions, and caching of basic HTTP GET requests. The `Store` trait facilitates this, and
//! by default, an in-memory store is used. This will work fine for simple single-process
//! applications, but if you intend to run multiple workers, an alternative Store must be
//! implemented. (In the future, we may offer some alternatives for common databases.
//! Contributions are welcome!)
//!
//! Some applications may need multiple configurations and `Client` instances, for example because
//! they serve multiple domains. In this case, we recommended creating short-lived `Client`s and
//! sharing the `Store` between them.
//!
//! The crate feature `simple-store` is enabled by default, but can be disabled to remove the Tokio
//! and Hyper dependencies. When disabled, the default `MemoryStore` will also not be available,
//! and a custom `Store` implementation must be provided.
//!
//! The minimum required Rust version is 1.46.

mod jwk;
mod jws;
mod misc;
mod store;

use misc::DynErr;
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use url::Url;

use crate::misc::DiscoveryDoc;

pub use crate::{misc::ResponseMode, store::*};

/// Errors that can result from `Builder::build`.
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("the configured server URL cannot be used")]
    InvalidServer,
    #[error("the configured redirect URI cannot be used")]
    InvalidRedirectUri,
    #[error("the configured server is not an origin (contains additional components)")]
    ServerNotAnOrigin,
    #[cfg(not(feature = "simple-store"))]
    #[error("no default store is available")]
    NoDefaultStore,
}

/// Errors that can result from `Client::start_auth`.
#[derive(Debug, Error)]
pub enum StartAuthError {
    #[error("could not fetch discovery document: {0}")]
    FetchDiscovery(#[source] FetchError),
    #[error("could not parse discovery document: {0}")]
    ParseDiscovery(#[source] serde_json::Error),
    #[error("could not generate nonce: {0}")]
    GenerateNonce(#[source] DynErr),
}

/// Errors that can result from `Client::verify`.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("could not fetch discovery document: {0}")]
    FetchDiscovery(#[source] FetchError),
    #[error("could not parse discovery document: {0}")]
    ParseDiscovery(#[source] serde_json::Error),
    #[error("could not fetch keys document: {0}")]
    FetchJwks(#[source] FetchError),
    #[error("could not parse keys document: {0}")]
    ParseJwks(#[source] serde_json::Error),
    #[error("could not verify token signature: {0}")]
    Signature(#[from] jws::VerifyError),
    #[error("invalid token payload: {0}")]
    InvalidPayload(#[source] serde_json::Error),
    #[error("the token issuer did not match")]
    IssuerInvalid,
    #[error("the token audience did not match")]
    AudienceInvalid,
    #[error("the token has expired")]
    TokenExpired,
    #[error("the token issue time is in the future")]
    IssuedInTheFuture,
    #[error("the server changed the email address, but is not trusted")]
    UntrustedServerChangedEmail,
    #[error("could not verify the session: {0}")]
    VerifySession(#[source] DynErr),
    #[error("the session is invalid or has expired")]
    InvalidSession,
}

/// A builder to configure a `Client`.
#[derive(Clone)]
pub struct Builder {
    store: Option<Arc<dyn Store>>,
    server: Option<Url>,
    trusted: bool,
    redirect_uri: Url,
    response_mode: ResponseMode,
    leeway: Duration,
}

impl Builder {
    fn new(redirect_uri: Url) -> Self {
        Builder {
            store: None,
            server: None,
            trusted: true,
            redirect_uri,
            response_mode: ResponseMode::default(),
            leeway: Duration::from_secs(180),
        }
    }

    /// Use the given `Store` for cache and session storage.
    ///
    /// If no store is specified, a default `MemoryStore` is created. This type of store has some
    /// limitations. See the documentation for `MemoryStore` for details.
    pub fn store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Configure the client to use a trusted broker.
    ///
    /// This allows you to override the default broker `https://broker.portier.io` with your own.
    /// The `url` must be an origin only. (Only scheme, host, and optionally port. No path, query
    /// string, etc.)
    pub fn broker(mut self, url: Url) -> Self {
        self.server = Some(url);
        self.trusted = true;
        self
    }

    /// Configure the client to use an untrusted identity provider.
    ///
    /// This is usually only used when implementing a broker. For configuring a relying party to
    /// use a custom broker, see `Builder::broker` instead.
    pub fn idp(mut self, url: Url) -> Self {
        self.server = Some(url);
        self.trusted = false;
        self
    }

    /// Configure the response mode to use. The default is `FormPost`.
    pub fn response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = mode;
        self
    }

    /// Configure the leeway to allow for timestamps in tokens. The default is 3 minutes.
    pub fn leeway(mut self, dur: Duration) -> Self {
        self.leeway = dur;
        self
    }

    /// Verify the configuration and build the client.
    pub fn build(self) -> Result<Client, BuildError> {
        let store = match self.store {
            Some(store) => store,
            #[cfg(feature = "simple-store")]
            None => Arc::new(MemoryStore::default()),
            #[cfg(not(feature = "simple-store"))]
            None => return Err(BuildError::NoDefaultStore),
        };

        let server = self
            .server
            .unwrap_or_else(|| "https://broker.portier.io".parse().unwrap());

        let server_origin = server.origin();
        if !server_origin.is_tuple() {
            return Err(BuildError::InvalidServer);
        }

        let client_origin = self.redirect_uri.origin();
        if !client_origin.is_tuple() {
            return Err(BuildError::InvalidRedirectUri);
        }

        let client_id = client_origin.ascii_serialization();
        let server_id = server_origin.ascii_serialization();

        // Verify server URL is an origin only. We can compare it with the ASCII origin, because
        // `Url` is internally ASCII as well. It may contain a `/` path, though.
        let server_str = server.as_str();
        if !(server_str == server_id
            || (server_str.len() == server_id.len() + 1
                && server_str.starts_with(&server_id)
                && server_str.ends_with('/')))
        {
            return Err(BuildError::ServerNotAnOrigin);
        }

        let mut discovery_url = server;
        discovery_url.set_path("/.well-known/openid-configuration");

        Ok(Client {
            store,
            server_id,
            discovery_url,
            trusted: self.trusted,
            redirect_uri: self.redirect_uri,
            client_id,
            response_mode: self.response_mode,
            leeway: self.leeway,
        })
    }
}

/// A client for performing Portier authentication.
///
/// Create a client using either `Client::builder` or `Client::new`. Sharing a client can be done
/// simply by reference, even across threads. All methods take an immutable reference to `self`
/// only.
///
/// If necessary, a client can also be cloned. This is not cheap, however, because settings within
/// are also cloned. The exception is the store, which is shared between clones.
#[derive(Clone)]
pub struct Client {
    store: Arc<dyn Store>,
    server_id: String,
    discovery_url: Url,
    trusted: bool,
    redirect_uri: Url,
    client_id: String,
    response_mode: ResponseMode,
    leeway: Duration,
}

impl Client {
    /// Create a builder-style struct to configure a Client.
    pub fn builder(redirect_uri: Url) -> Builder {
        Builder::new(redirect_uri)
    }

    /// Create a client with default settings.
    ///
    /// This uses a `MemoryStore`, which has some limitations. See the documentation for
    /// `MemoryStore` for details.
    #[cfg(feature = "simple-store")]
    pub fn new(redirect_uri: Url) -> Self {
        Builder::new(redirect_uri).build().unwrap()
    }

    /// Create a login session for the given email, and return a URL to redirect the user agent
    /// (browser) to so authentication can continue.
    ///
    /// If performing the redirect in the HTTP response, the recommended method is to send a 303
    /// HTTP status code with the `Location` header set to the URL. But other solutions are
    /// possible, such as fetching this URL using a request from client-side JavaScript.
    ///
    /// The caller may add a `state` query parameter to the returned URL, which is passed verbatim
    /// to the redirect URI after the user returns.
    pub async fn start_auth(&self, email: &str) -> Result<Url, StartAuthError> {
        let discovery = self
            .store
            .fetch(self.discovery_url.clone())
            .await
            .map_err(StartAuthError::FetchDiscovery)?;
        let discovery: DiscoveryDoc =
            serde_json::from_slice(&discovery).map_err(StartAuthError::ParseDiscovery)?;

        let nonce = self
            .store
            .new_nonce(email.to_owned())
            .await
            .map_err(StartAuthError::GenerateNonce)?;
        let mut auth_url = discovery.authorization_endpoint;
        auth_url
            .query_pairs_mut()
            .append_pair("login_hint", email)
            .append_pair("scope", "openid email")
            .append_pair("nonce", &nonce)
            .append_pair("response_type", "id_token")
            .append_pair("response_mode", self.response_mode.as_str())
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", self.redirect_uri.as_str());
        Ok(auth_url)
    }

    /// Verify `token` and return a verified email address.
    ///
    /// The token is delivered by the user agent (browser) directly according to the `redirect_uri`
    /// and `response_mode` configured when the `Client` was created.
    pub async fn verify(&self, token: &str) -> Result<String, VerifyError> {
        let discovery = self
            .store
            .fetch(self.discovery_url.clone())
            .await
            .map_err(VerifyError::FetchDiscovery)?;
        let discovery: DiscoveryDoc =
            serde_json::from_slice(&discovery).map_err(VerifyError::ParseDiscovery)?;

        let jwks = self
            .store
            .fetch(discovery.jwks_uri)
            .await
            .map_err(VerifyError::FetchJwks)?;
        let jwks: jwk::KeySet = serde_json::from_slice(&jwks).map_err(VerifyError::ParseJwks)?;

        // Basic token signature verification, parsing, and claim validation.
        #[derive(Deserialize)]
        struct Payload {
            iss: String,
            aud: String,
            email: String,
            email_original: Option<String>,
            #[serde(deserialize_with = "misc::deserialize_timestamp")]
            iat: u64,
            #[serde(deserialize_with = "misc::deserialize_timestamp")]
            exp: u64,
            nonce: String,
        }
        let payload = jws::verify(token, &jwks.keys)?;
        let payload: Payload =
            serde_json::from_slice(&payload).map_err(VerifyError::InvalidPayload)?;
        if payload.iss != self.server_id {
            return Err(VerifyError::IssuerInvalid);
        }
        if payload.aud != self.client_id {
            return Err(VerifyError::AudienceInvalid);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current system time is before Unix epoch")
            .as_secs();

        let exp_stretched = payload
            .exp
            .checked_add(self.leeway.as_secs())
            .unwrap_or(u64::MIN);
        if exp_stretched < now {
            return Err(VerifyError::TokenExpired);
        }

        let iat_stretched = payload
            .iat
            .checked_sub(self.leeway.as_secs())
            .unwrap_or(u64::MAX);
        if now < iat_stretched {
            return Err(VerifyError::IssuedInTheFuture);
        }

        // If verifying an IdP token, it can't change the email address per spec. The spec assumes
        // the client is a Broker, in this case, and has already done normalization.
        if !self.trusted {
            match payload.email_original {
                None => {}
                Some(ref orig) if orig == &payload.email => {}
                Some(_) => return Err(VerifyError::UntrustedServerChangedEmail),
            }
        }

        // Check the pair (nonce, email_original) exists in the store.
        let email_original = match payload.email_original {
            Some(email) => email,
            None => payload.email.clone(),
        };
        if !self
            .store
            .consume_nonce(payload.nonce, email_original)
            .await
            .map_err(VerifyError::VerifySession)?
        {
            return Err(VerifyError::InvalidSession);
        }

        Ok(payload.email)
    }
}
