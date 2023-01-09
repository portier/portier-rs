use serde::{de::Visitor, Deserialize};
use std::{fmt, future::Future, pin::Pin};
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

/// Function used to deserialize Unix timestamps in a JWT.
///
/// Some JWT implementations produce floating points for `iat` / `exp` values.
pub fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // This visitor specifically implements only the methods expected to be called by
    // serde_json. We can ignore i64 / negative values, and treat them as invalid.
    struct TimestampVisitor;
    impl<'de> Visitor<'de> for TimestampVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a positive number")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v as u64)
        }
    }
    deserializer.deserialize_any(TimestampVisitor)
}

pub mod base64url {
    pub use base64::prelude::*;

    #[inline]
    pub fn encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(data)
    }

    #[inline]
    pub fn decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64_URL_SAFE_NO_PAD.decode(data)
    }
}
