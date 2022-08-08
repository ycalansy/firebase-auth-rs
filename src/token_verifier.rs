use std::collections::HashMap;

use anyhow::{anyhow, Context};
use chrono::{Duration, NaiveDateTime, Utc};
use reqwest::{header::HeaderMap, StatusCode};
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, MutexGuard};
use x509_certificate::{CapturedX509Certificate, KeyAlgorithm};

use super::auth::{
    has_auth_error_code, is_id_token_revoked, is_session_cookie_revoked, Token, AUTH_ERROR_CODE,
    FIREBASE_AUDIENCE,
};
use super::clock::{Clock, SystemClock};
use super::error::{Error, FirebaseError, FirebaseErrorCode, Result};
use super::json::JsonObject;
use super::json_object;
use super::token_generator::JwtHeader;

const ID_TOKEN_CERT_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

const SESSION_COOKIE_CERT_URL: &str =
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys";

const ID_TOKEN_ISSUER_PREFIX: &str = "https://securetoken.google.com/";
const SESSION_COOKIE_ISSUER_PREFIX: &str = "https://session.firebase.google.com/";
const CERTIFICATE_FETCH_FAILED: &str = "CERTIFICATE_FETCH_FAILED";
const ID_TOKEN_EXPIRED: &str = "ID_TOKEN_EXPIRED";
const ID_TOKEN_INVALID: &str = "ID_TOKEN_INVALID";
const SESSION_COOKIE_EXPIRED: &str = "SESSION_COOKIE_EXPIRED";
const SESSION_COOKIE_INVALID: &str = "SESSION_COOKIE_INVALID";
const CLOCK_SKEW_SECONDS: i64 = 300;

pub fn is_certificate_fetch_failed(e: &Error) -> bool {
    has_auth_error_code(e, CERTIFICATE_FETCH_FAILED)
}

pub fn is_id_token_expired(e: &Error) -> bool {
    has_auth_error_code(e, ID_TOKEN_EXPIRED)
}

pub fn is_id_token_invalid(e: &Error) -> bool {
    has_auth_error_code(e, ID_TOKEN_INVALID) || is_id_token_expired(e) || is_id_token_revoked(e)
}

pub fn is_session_cookie_expired(e: &Error) -> bool {
    has_auth_error_code(e, SESSION_COOKIE_EXPIRED)
}

pub fn is_session_cookie_invalid(e: &Error) -> bool {
    has_auth_error_code(e, SESSION_COOKIE_INVALID)
        || is_session_cookie_expired(e)
        || is_session_cookie_revoked(e)
}

pub(crate) struct TokenVerifier<K: KeySource, C: Clock> {
    short_name: String,
    articled_short_name: String,
    doc_url: String,
    project_id: String,
    issuer_prefix: String,
    invalid_token_code: String,
    expired_token_code: String,
    key_source: K,
    clock: C,
}

impl TokenVerifier<HttpKeySource<SystemClock>, SystemClock> {
    pub(crate) fn new_id_token_verifier(project_id: String) -> Self {
        let http_client = reqwest::Client::default();
        Self {
            short_name: "ID token".to_string(),
            articled_short_name: "an ID token".to_string(),
            doc_url: "https://firebase.google.com/docs/auth/admin/verify-id-tokens".to_string(),
            project_id,
            issuer_prefix: ID_TOKEN_ISSUER_PREFIX.to_string(),
            invalid_token_code: ID_TOKEN_INVALID.to_string(),
            expired_token_code: ID_TOKEN_EXPIRED.to_string(),
            key_source: HttpKeySource::new(ID_TOKEN_CERT_URL.to_string(), http_client),
            clock: SystemClock,
        }
    }

    pub(crate) fn new_session_cookie_verifier(project_id: String) -> Self {
        let http_client = reqwest::Client::default();
        Self {
            short_name: "session cookie".to_string(),
            articled_short_name: "a session cookie".to_string(),
            doc_url: "https://firebase.google.com/docs/auth/admin/manage-cookies".to_string(),
            project_id,
            issuer_prefix: SESSION_COOKIE_ISSUER_PREFIX.to_string(),
            invalid_token_code: SESSION_COOKIE_INVALID.to_string(),
            expired_token_code: SESSION_COOKIE_EXPIRED.to_string(),
            key_source: HttpKeySource::new(SESSION_COOKIE_CERT_URL.to_string(), http_client),
            clock: SystemClock,
        }
    }
}

impl<K: KeySource, C: Clock> TokenVerifier<K, C> {
    pub(crate) async fn verify_token(&self, token: String) -> Result<Token> {
        if self.project_id.is_empty() {
            return Err(anyhow!("project id not available"))?;
        }

        let payload = self.verify_content(&token)?;

        self.verify_timestamps(&payload)?;
        self.verify_signature(&token).await?;

        Ok(payload)
    }

    fn verify_content(&self, token: &str) -> Result<Token> {
        if token.is_empty() {
            return Err(FirebaseError {
                error_code: FirebaseErrorCode::InvalidArgument,
                string: format!("{} must be a non-empty string", self.short_name),
                ext: json_object! {
                    AUTH_ERROR_CODE.to_string() => self.invalid_token_code.as_str().into()
                },
            })?;
        }

        let payload = self
            .verify_header_and_body(token)
            .map_err(|e| FirebaseError {
                error_code: FirebaseErrorCode::InvalidArgument,
                string: format!(
                    "{}; see {} for details on how to retrieve a valid {}",
                    e.to_string(),
                    self.doc_url,
                    self.short_name
                ),
                ext: json_object! {
                    AUTH_ERROR_CODE.to_string() => self.invalid_token_code.as_str().into()
                },
            })?;

        Ok(payload)
    }

    fn verify_header_and_body(&self, token: &str) -> Result<Token> {
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() != 3 {
            return Err(anyhow!("incorrect number of segments"))?;
        }

        let header: JwtHeader = decode(segments[0])?;
        let payload: Token = decode(segments[1])?;
        let issuer = self.issuer_prefix.to_owned() + &self.project_id;

        if header.key_id.is_empty() {
            if payload.audience == FIREBASE_AUDIENCE {
                return Err(anyhow!(
                    "expected {} but got a custom token",
                    self.articled_short_name
                ))?;
            }
            return Err(anyhow!("{} has no 'kid' header", self.short_name))?;
        }
        if header.algorithm != "RS256" {
            return Err(anyhow!(
                "{} has invalid algorithm; expected 'RS256' but got {:?}",
                self.short_name,
                header.algorithm
            ))?;
        }
        if payload.audience != self.project_id {
            return Err(anyhow!(
                "{} has invalid 'aud' (audience) claim; expected {:?} but got {:?}; {}",
                self.short_name,
                self.project_id,
                payload.audience,
                self.get_project_id_match_message()
            ))?;
        }
        if payload.issuer != issuer {
            return Err(anyhow!(
                "{} has invalid 'iss' (issuer) claim; expected {:?} but got {:?}; {}",
                self.short_name,
                issuer,
                payload.issuer,
                self.get_project_id_match_message()
            ))?;
        }
        if payload.subject.is_empty() {
            return Err(anyhow!(
                "{} has empty 'sub' (subject) claim",
                self.short_name
            ))?;
        }
        if payload.subject.len() > 128 {
            return Err(anyhow!(
                "{} has a 'sub' (subject) claim longer than 128 characters",
                self.short_name
            ))?;
        }

        let mut payload = payload;
        payload.uid = payload.subject.to_owned();

        const STANDARD_CLAIMS: [&'static str; 6] = ["iss", "aud", "exp", "iat", "sub", "uid"];

        let mut custom_claims: JsonObject = decode(segments[1])?;

        for standard_claim in STANDARD_CLAIMS {
            custom_claims.remove(standard_claim);
        }

        payload.claims = Some(custom_claims);

        Ok(payload)
    }

    fn get_project_id_match_message(&self) -> String {
        format!("make sure the {} comes from the same Firebase project as the credential used to authenticate this SDK", self.short_name)
    }

    fn verify_timestamps(&self, payload: &Token) -> Result<()> {
        if (payload.issued_at - CLOCK_SKEW_SECONDS) > self.clock.now().timestamp() {
            return Err(FirebaseError {
                error_code: FirebaseErrorCode::InvalidArgument,
                string: format!(
                    "{} issued at future timestamp: {}",
                    self.short_name, payload.issued_at
                ),
                ext: json_object! {
                    AUTH_ERROR_CODE.to_string() => self.invalid_token_code.as_str().into()
                },
            })?;
        }

        if (payload.expires + CLOCK_SKEW_SECONDS) < self.clock.now().timestamp() {
            return Err(FirebaseError {
                error_code: FirebaseErrorCode::InvalidArgument,
                string: format!("{} has expired at: {}", self.short_name, payload.expires),
                ext: json_object! {
                    AUTH_ERROR_CODE.to_string() => self.expired_token_code.as_str().into()
                },
            })?;
        }

        Ok(())
    }

    async fn verify_signature(&self, token: &str) -> Result<()> {
        let keys = self.key_source.keys().await.map_err(|e| FirebaseError {
            error_code: FirebaseErrorCode::Unknown,
            string: e.to_string(),
            ext: json_object! {
                AUTH_ERROR_CODE.to_string() => CERTIFICATE_FETCH_FAILED.into()
            },
        })?;

        if !self.verify_signature_with_keys(token, keys) {
            return Err(FirebaseError {
                error_code: FirebaseErrorCode::InvalidArgument,
                string: "failed to verify token signature".to_string(),
                ext: json_object! {
                    AUTH_ERROR_CODE.to_string() => self.invalid_token_code.as_str().into()
                },
            })?;
        }

        Ok(())
    }

    fn verify_signature_with_keys(&self, token: &str, keys: PublicKeyMap) -> bool {
        let segemnts: Vec<&str> = token.split('.').collect();
        let header: JwtHeader = decode(segemnts[0]).unwrap_or_default();
        let mut verified = false;

        for (kid, key) in keys {
            if header.key_id.is_empty() || header.key_id == kid {
                if verify_jwt_signature(&segemnts, key).is_ok() {
                    verified = true;
                    break;
                }
            }
        }

        verified
    }
}

fn decode<T: DeserializeOwned>(segment: &str) -> Result<T> {
    let decoded = base64::decode_config(segment, base64::URL_SAFE_NO_PAD)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn verify_jwt_signature(segments: &Vec<&str>, key: CapturedX509Certificate) -> Result<()> {
    let content = format!("{}.{}", segments[0], segments[1]);
    let signature = base64::decode_config(segments[2], base64::URL_SAFE_NO_PAD)?;
    Ok(key.verify_signed_data_with_algorithm(content, signature, &RSA_PKCS1_2048_8192_SHA256)?)
}

#[async_trait::async_trait]
pub(crate) trait KeySource {
    async fn keys(&self) -> Result<PublicKeyMap>;
}

type PublicKeyMap = HashMap<String, CapturedX509Certificate>;

struct Cache {
    public_keys: PublicKeyMap,
    expiry_time: NaiveDateTime,
}

pub(crate) struct HttpKeySource<C: Clock + Sync + Send> {
    key_uri: String,
    http_client: reqwest::Client,
    cache: Mutex<Cache>,
    clock: C,
}

impl HttpKeySource<SystemClock> {
    fn new(key_uri: String, http_client: reqwest::Client) -> Self {
        Self {
            key_uri,
            http_client,
            cache: Mutex::new(Cache {
                public_keys: HashMap::new(),
                expiry_time: Utc::now().naive_utc(),
            }),
            clock: SystemClock,
        }
    }
}

#[async_trait::async_trait]
impl<C: Clock + Sync + Send> KeySource for HttpKeySource<C> {
    async fn keys(&self) -> Result<PublicKeyMap> {
        let mut cache = self.cache.lock().await;
        if cache.public_keys.len() == 0 || self.cache_expired(cache.expiry_time) {
            self.refresh_keys(&mut cache).await?;
        }
        Ok(cache.public_keys.clone())
    }
}

impl<C: Clock + Sync + Send> HttpKeySource<C> {
    fn cache_expired(&self, expiry_time: NaiveDateTime) -> bool {
        expiry_time < self.clock.now()
    }

    async fn refresh_keys(&self, cache: &mut MutexGuard<'_, Cache>) -> Result<()> {
        cache.public_keys.clear();

        let resp = self.http_client.get(&self.key_uri).send().await?;

        let headers = resp.headers().clone();
        let status = resp.status();
        let contents = resp.text().await?;

        if status != StatusCode::OK {
            return Err(anyhow!(
                "invalid response ({}) while retrieving public keys: {}",
                status.as_u16(),
                contents
            ))?;
        }

        let public_keys = parse_public_keys(contents)?;

        let max_age = find_max_age(headers)?;

        cache.public_keys = public_keys;
        cache.expiry_time = self.clock.now() + max_age;

        Ok(())
    }
}

fn parse_public_keys(data: String) -> Result<PublicKeyMap> {
    let data: HashMap<String, String> = serde_json::from_str(&data)?;
    let mut public_keys: PublicKeyMap = HashMap::with_capacity(data.len());

    for (kid, key) in data {
        let public_key = parse_public_key(key)?;
        public_keys.insert(kid, public_key);
    }

    Ok(public_keys)
}

fn parse_public_key(key: String) -> Result<CapturedX509Certificate> {
    let certificate = CapturedX509Certificate::from_pem(key.as_bytes())
        .with_context(|| "failed to decode the certificate as PEM")?;

    match certificate.key_algorithm() {
        Some(algorithm) => match algorithm {
            KeyAlgorithm::Rsa => Ok(certificate),
            _ => Err(anyhow!("certificate is not an RSA key"))?,
        },
        None => Err(anyhow!("certificate is not an RSA key"))?,
    }
}

fn find_max_age(headers: HeaderMap) -> Result<Duration> {
    if let Some(cache_control) = headers.get("cache-control") {
        let parts: Vec<&str> = cache_control
            .to_str()?
            .split(',')
            .map(|part| part.trim())
            .collect();

        for part in parts {
            if part.starts_with("max-age=") {
                let second = part.trim_start_matches("max-age=").parse::<i64>()?;
                return Ok(Duration::seconds(second));
            }
        }
    }
    Err(anyhow!("could not find expiry time from HTTP headers"))?
}
