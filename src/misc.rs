use serde::Deserialize;
use std::{future::Future, pin::Pin};
use url::Url;

pub type DynErr = Box<dyn std::error::Error + Send + Sync>;
pub type DynFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type DynRes<T> = Result<T, DynErr>;
pub type DynFutRes<T> = DynFut<DynRes<T>>;

/// Supported response modes.
///
/// The response mode specifies how the server instructs the user agent to return a response to the
/// `redirect_uri` of the client.
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum ResponseMode {
    /// Send the response data in the URL fragment.
    ///
    /// Additional client-side JavaScript is required to use this mode, because the URL fragment is
    /// not sent to the server.
    Fragment,
    /// Send the response data in a POST request with an `application/x-www-form-urlencoded` body.
    FormPost,
}

impl ResponseMode {
    /// Convert to the `response_mode` query string value.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
        }
    }
}

impl Default for ResponseMode {
    fn default() -> Self {
        ResponseMode::FormPost
    }
}

/// OpenID Connect discovery document.
#[derive(Deserialize)]
pub struct DiscoveryDoc {
    pub jwks_uri: Url,
    pub authorization_endpoint: Url,
}

/// Parse URL-safe base64.
pub fn base64url_decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD)
}
