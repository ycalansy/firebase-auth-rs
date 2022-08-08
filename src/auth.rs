use anyhow::anyhow;
use serde::Deserialize;

use super::clock::Clock;
use super::error::{Error, Result};
use super::json::JsonObject;
use super::token_generator::{
    AppEngineSigner, CryptoSigner, CustomToken, IamSigner, JwtHeader, JwtInfo,
};
use super::token_verifier::{KeySource, TokenVerifier};

pub(crate) const AUTH_ERROR_CODE: &str = "authErrorCode";
const EMULATOR_HOST_ENV_VAR: &str = "FIREBASE_AUTH_EMULATOR_HOST";
const DEFAULT_AUTH_URL: &str = "https://identitytoolkit.googleapis.com";
const ONE_HOUR_IN_SECONDS: i64 = 3600;

pub(crate) const FIREBASE_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

const ID_TOKEN_REVOKED: &str = "ID_TOKEN_REVOKED";
const USER_DISABLED: &str = "USER_DISABLED";
const SESSION_COOKIE_REVOKED: &str = "SESSION_COOKIE_REVOKED";
const TENANT_IDMISMATCH: &str = "TENANT_ID_MISMATCH";

pub struct Config {
    pub http_client: reqwest::Client,
    pub project_id: String,
    pub service_account_id: Option<String>,
    pub version: String,
}

pub struct Client {}

#[derive(Debug, Deserialize)]
pub struct Token {
    pub auth_time: i64,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "exp")]
    pub expires: i64,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(default)]
    pub uid: String,
    pub firebase: FirebaseInfo,
    pub claims: Option<JsonObject>,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseInfo {
    pub sign_in_provider: String,
    pub tenant: Option<String>,
    pub identities: JsonObject,
}

pub(crate) struct BaseClient<K: KeySource, C: Clock, S: CryptoSigner> {
    user_management_endpoint: String,
    provider_config_endpoint: String,
    tenant_management_endpoint: String,
    project_id: String,
    tenant_id: String,
    http_client: reqwest::Client,
    id_token_verifier: TokenVerifier<K, C>,
    cookie_verifier: TokenVerifier<K, C>,
    signer: S,
    clock: C,
}

impl<K: KeySource, C: Clock, S: CryptoSigner> BaseClient<K, C, S> {
    async fn custom_token(&self, uid: &str) -> Result<String> {
        self.custom_token_with_claims(uid, None).await
    }

    async fn custom_token_with_claims(
        &self,
        uid: &str,
        dev_claims: Option<JsonObject>,
    ) -> Result<String> {
        let iss = self.signer.email().await?;

        if uid.is_empty() || uid.len() > 128 {
            return Err(anyhow!(
                "uid must be non-empty, and not longer than 128 characters"
            ))?;
        }

        if let Some(ref claims) = dev_claims {
            let mut disallowed: Vec<&str> = Vec::new();

            for k in claims.keys() {
                disallowed.push(k.as_str());
            }

            if disallowed.len() == 1 {
                return Err(anyhow!(
                    "developer claim {:?} is reserved and cannot be specified",
                    disallowed.first().unwrap()
                ))?;
            } else if disallowed.len() > 1 {
                return Err(anyhow!(
                    "developer claims {:?} is reserved and cannot be specified",
                    disallowed.join(", ")
                ))?;
            }
        }

        let now = self.clock.now().timestamp();

        let info = JwtInfo {
            header: JwtHeader {
                algorithm: self.signer.algorithm(),
                r#type: "JWT".to_string(),
                key_id: "".to_string(),
            },
            payload: CustomToken {
                iss: iss.clone(),
                aud: FIREBASE_AUDIENCE.to_string(),
                exp: now + ONE_HOUR_IN_SECONDS,
                iat: now,
                sub: iss,
                uid: uid.to_string(),
                tenant_id: self.tenant_id.to_owned(),
                claims: dev_claims,
            },
        };

        Ok(info.token(&self.signer).await?)
    }
}

pub fn is_tenant_idmismatch(e: &Error) -> bool {
    has_auth_error_code(e, TENANT_IDMISMATCH)
}

pub fn is_id_token_revoked(e: &Error) -> bool {
    has_auth_error_code(e, ID_TOKEN_REVOKED)
}

pub fn is_user_disabled(e: &Error) -> bool {
    has_auth_error_code(e, USER_DISABLED)
}

pub fn is_session_cookie_revoked(e: &Error) -> bool {
    has_auth_error_code(e, SESSION_COOKIE_REVOKED)
}

pub(crate) fn has_auth_error_code<C>(e: &Error, code: C) -> bool
where
    C: Into<serde_json::Value>,
{
    match e {
        Error::Firebase(fe) => fe.ext.get(AUTH_ERROR_CODE) == Some(&code.into()),
        Error::Other(_) => false,
    }
}

#[cfg(not(app_engine_crypto_signer))]
fn new_crypto_signer(conf: Config) -> impl CryptoSigner {
    IamSigner::new(conf)
}

#[cfg(app_engine_crypto_signer)]
fn new_crypto_signer(conf: Config) -> impl CryptoSigner {
    AppEngineSigner::new(conf)
}
