use serde::{de::Error, Deserialize};

use crate::misc::base64url_decode;

/// Document containing a set of JWKs.
///
/// Deserializes RFC 7517, Section 5.
#[derive(Deserialize)]
pub struct KeySet {
    pub keys: Vec<Key>,
}

/// A single JWK.
///
/// Deserializes RFC 7517, Section 4.
#[derive(Deserialize)]
pub struct Key {
    pub kid: String,
    #[serde(flatten)]
    pub data: KeyData,
}

/// The type of key and inner data, based on the `kty` field.
///
/// Deserializes RFC 7517, Section 4.1.
#[derive(Deserialize)]
#[serde(tag = "kty")]
pub enum KeyData {
    #[serde(rename = "RSA")]
    Rsa(RsaKey),
    #[serde(rename = "OKP")]
    Okp(OkpKey),
    #[serde(other)]
    Unknown,
}

/// Deserializes URL-safe base64, often used in JWK fields.
#[derive(Debug)]
pub struct Binary(Vec<u8>);

impl<'de> Deserialize<'de> for Binary {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: &str = Deserialize::deserialize(de)?;
        base64url_decode(data).map(Self).map_err(Error::custom)
    }
}

impl AsRef<[u8]> for Binary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// RSA-specific fields of a JWK.
///
/// Deserializes RFC 7518, Section 6.3.
#[derive(Deserialize)]
pub struct RsaKey {
    pub alg: RsaAlg,
    pub n: Binary,
    pub e: Binary,
}

/// JWS algorithm types for RSA keys.
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum RsaAlg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(other)]
    Unknown,
}

/// Octet Key Pair (OKP) specific fields of a JWK. Used by Ed25519 and Ed448.
///
/// Deserializes RFC 8037, Section 2.
#[derive(Deserialize)]
pub struct OkpKey {
    pub alg: OkpAlg,
    pub crv: OkpCurve,
    pub x: Binary,
}

/// JWS algorithm types for RSA keys.
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum OkpAlg {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(other)]
    Unknown,
}

/// OKP curve types.
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum OkpCurve {
    Ed25519,
    #[serde(other)]
    Unknown,
}
