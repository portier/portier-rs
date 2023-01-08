use ring::signature;
use serde::Deserialize;
use thiserror::Error;

use crate::{jwk, misc::base64url};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("the token must consist of three dot-separated parts")]
    IncorrectFormat,
    #[error("token part {index} contained invalid base64: {reason}")]
    InvalidPartBase64 {
        index: usize,
        reason: base64::DecodeError,
    },
    #[error("the token header contained invalid JSON: {0}")]
    InvalidHeaderJson(serde_json::Error),
    #[error("the token 'kid' could not be found in the JWKs document: {kid}")]
    KidNotMatched { kid: String },
    #[error("the matching JWK is of an unsupported type")]
    UnsupportedKeyType,
    #[error("the token signature did not validate using the matching JWK")]
    BadSignature,
}

/// Verify a JWS signature, returning the payload as a `Value` if successful.
pub fn verify<'a>(
    input: &'a str,
    keys: impl IntoIterator<Item = &'a jwk::Key>,
) -> Result<Vec<u8>, VerifyError> {
    // Split the token up in parts.
    let mut parts = input.split('.');
    let header = parts.next().ok_or(VerifyError::IncorrectFormat)?;
    let payload = parts.next().ok_or(VerifyError::IncorrectFormat)?;
    let signature = parts.next().ok_or(VerifyError::IncorrectFormat)?;
    if parts.next().is_some() {
        return Err(VerifyError::IncorrectFormat);
    }

    // Slice the signed part of the message, before we start decoding parts.
    let message_len = header.len() + payload.len() + 1;
    let message = input[..message_len].as_bytes();

    // Decode all parts.
    let header = base64url::decode(header)
        .map_err(|reason| VerifyError::InvalidPartBase64 { index: 1, reason })?;
    let payload = base64url::decode(payload)
        .map_err(|reason| VerifyError::InvalidPartBase64 { index: 2, reason })?;
    let signature = base64url::decode(signature)
        .map_err(|reason| VerifyError::InvalidPartBase64 { index: 3, reason })?;

    // Parse the header and find the key ID.
    #[derive(Deserialize)]
    struct Header {
        kid: String,
    }
    let header: Header = serde_json::from_slice(&header).map_err(VerifyError::InvalidHeaderJson)?;

    // Look for they key ID in the JWKs.
    let matched_keys: Vec<&jwk::Key> = keys
        .into_iter()
        .filter(|key| key.kid == header.kid)
        .collect();

    // Verify that we found exactly one key matching the key ID.
    if matched_keys.len() != 1 {
        return Err(VerifyError::KidNotMatched { kid: header.kid });
    }
    let key = matched_keys.first().unwrap();

    // Verify the signature.
    match key.data {
        jwk::KeyData::Okp(jwk::OkpKey {
            alg: jwk::OkpAlg::EdDsa,
            crv: jwk::OkpCurve::Ed25519,
            ref x,
        }) => {
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, &signature)
                .map_err(|_err| VerifyError::BadSignature)?;
        }
        jwk::KeyData::Rsa(jwk::RsaKey {
            alg: jwk::RsaAlg::Rs256,
            ref n,
            ref e,
        }) => {
            signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, &signature)
                .map_err(|_err| VerifyError::BadSignature)?;
        }
        _ => return Err(VerifyError::UnsupportedKeyType),
    }

    // Return the payload.
    Ok(payload)
}
