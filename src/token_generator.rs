use std::time::Duration;

use anyhow::{anyhow, Context};
use prost::Message;
use reqwest::{
    header::{HeaderName, HeaderValue},
    StatusCode,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use x509_certificate::{InMemorySigningKeyPair, Signer};

use super::auth::Config;
use super::error::Result;
use super::json::JsonObject;

const ALGORITHM_RS256: &str = "RS256";

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct JwtHeader {
    #[serde(rename = "alg")]
    pub(crate) algorithm: String,
    #[serde(rename = "typ")]
    pub(crate) r#type: String,
    #[serde(rename = "kid")]
    pub(crate) key_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CustomToken {
    pub(crate) iss: String,
    pub(crate) aud: String,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
    pub(crate) sub: String,
    pub(crate) uid: String,
    pub(crate) tenant_id: String,
    pub(crate) claims: Option<JsonObject>,
}

pub(crate) struct JwtInfo {
    pub(crate) header: JwtHeader,
    pub(crate) payload: CustomToken,
}

impl JwtInfo {
    fn encode<D: Serialize>(&self, data: D) -> Result<String> {
        let data = serde_json::to_string(&data)?;
        Ok(base64::encode_config(data, base64::URL_SAFE_NO_PAD))
    }

    pub(crate) async fn token<S: CryptoSigner>(&self, signer: &S) -> Result<String> {
        let header = self.encode(&self.header)?;
        let payload = self.encode(&self.payload)?;
        let token_data = format!("{}.{}", header, payload);
        let signautre = signer.sign(token_data.as_bytes()).await?;

        Ok(format!(
            "{}.{}",
            token_data,
            base64::encode_config(signautre, base64::URL_SAFE_NO_PAD)
        ))
    }
}

#[async_trait::async_trait]
pub(crate) trait CryptoSigner {
    fn algorithm(&self) -> String;
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn email(&self) -> Result<String>;
}

struct ServiceAccount {
    private_key: String,
    client_email: String,
}

pub(crate) struct ServiceAccountSigner {
    private_key: InMemorySigningKeyPair,
    client_email: String,
}

impl ServiceAccountSigner {
    pub(crate) fn new(sa: ServiceAccount) -> Result<Self> {
        Ok(Self {
            private_key: x509_certificate::InMemorySigningKeyPair::from_pkcs8_pem(sa.private_key)?,
            client_email: sa.client_email,
        })
    }
}

#[async_trait::async_trait]
impl CryptoSigner for ServiceAccountSigner {
    fn algorithm(&self) -> String {
        ALGORITHM_RS256.to_string()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.private_key.try_sign(data)?.as_ref().to_vec())
    }

    async fn email(&self) -> Result<String> {
        Ok(self.client_email.to_owned())
    }
}

#[derive(Debug, Serialize)]
struct SignRequest {
    payload: String,
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    #[serde(rename = "signedBlob")]
    signature: String,
}

pub(crate) struct IamSigner {
    default_http_client: reqwest::Client,
    http_client: reqwest::Client,
    service_acct: Mutex<String>,
    metadata_host: String,
    iam_host: String,
}

impl IamSigner {
    pub(crate) fn new(conf: Config) -> Self {
        Self {
            default_http_client: reqwest::Client::default(),
            http_client: conf.http_client,
            service_acct: Mutex::new(conf.service_account_id.unwrap()),
            metadata_host: "http://metadata.google.internal".to_string(),
            iam_host: "https://iamcredentials.googleapis.com".to_string(),
        }
    }

    async fn call_metadata_service(&self) -> Result<String> {
        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/default/email",
            self.metadata_host
        );

        let result = self
            .default_http_client
            .get(url)
            .header(
                HeaderName::from_static("metadata-flavor"),
                HeaderValue::from_static("Google"),
            )
            .send()
            .await?
            .text()
            .await?;

        let result = result.trim();

        if result.is_empty() {
            return Err(anyhow!("unexpected response from metadata service"))?;
        }

        Ok(result.to_string())
    }
}

#[async_trait::async_trait]
impl CryptoSigner for IamSigner {
    fn algorithm(&self) -> String {
        ALGORITHM_RS256.to_string()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let account = self.email().await?;

        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:signBlob",
            self.iam_host, account,
        );

        let response: SignResponse = self
            .http_client
            .post(url)
            .json(&SignRequest {
                payload: base64::encode(data),
            })
            .send()
            .await?
            .json()
            .await?;

        Ok(base64::decode(response.signature)?)
    }

    async fn email(&self) -> Result<String> {
        let mut service_acct = self.service_acct.lock().await;
        if !service_acct.is_empty() {
            return Ok(service_acct.to_owned());
        }

        let result = self.call_metadata_service().await.map_err(|e| {
            let msg = format!(
                "failed to determine service account: {:?}; initialize the SDK with service \
            account credentials or specify a service account with iam.serviceAccounts.signBlob \
            permission; refer to https://firebase.google.com/docs/auth/admin/create-custom-tokens \
            for more details on creating custom tokens",
                e
            );

            anyhow!(msg)
        })?;

        *service_acct = result.clone();

        Ok(result)
    }
}

pub(crate) mod app_engine_grpc {
    tonic::include_proto!("appengine");
}

pub(crate) mod gcp_remote_grpc {
    tonic::include_proto!("remote_api");
}

pub(crate) struct AppEngineSigner {
    http_client: reqwest::Client,
}

impl AppEngineSigner {
    pub(crate) fn new(conf: Config) -> Self {
        Self {
            http_client: conf.http_client,
        }
    }

    async fn call<I, O>(&self, service: &str, method: &str, input: I) -> Result<O>
    where
        I: Message,
        O: Message + Default,
    {
        let mut buf = Vec::new();
        input.encode(&mut buf)?;

        let request = gcp_remote_grpc::Request {
            service_name: service.to_string(),
            method: method.to_string(),
            request: buf,
            request_id: None,
        };

        let mut buf = Vec::new();
        request.encode(&mut buf)?;

        let response: gcp_remote_grpc::Response = self.post(buf, Duration::from_secs(60)).await?;

        if let Some(e) = response.rpc_error {
            return Err(anyhow!(e.detail.unwrap()))?;
        }
        if let Some(e) = response.application_error {
            return Err(anyhow!(e.detail))?;
        }
        if response.exception.is_some() || response.java_exception.is_some() {
            return Err(anyhow!("service bridge returned exception"))?;
        }

        let data = response.response.unwrap();

        Ok(Message::decode(data.as_slice())?)
    }

    async fn post<O: Message + Default>(&self, body: Vec<u8>, timeout: Duration) -> Result<O> {
        let api_url = self.api_url();

        let deadline_header_value = timeout.as_secs_f64().to_string();

        let response = self
            .http_client
            .post(api_url)
            .header(
                HeaderName::from_static("x-google-rpc-service-endpoint"),
                HeaderValue::from_static("app-engine-apis"),
            )
            .header(
                HeaderName::from_static("x-google-rpc-service-method"),
                HeaderValue::from_static("/VMRemoteAPI.CallRemoteAPI"),
            )
            .header(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/octet-stream"),
            )
            .header(
                HeaderName::from_static("x-google-rpc-service-deadline"),
                HeaderValue::from_str(deadline_header_value.as_str())?,
            )
            .body(body)
            .timeout(timeout)
            .send()
            .await
            .with_context(|| "service bridge HTTP failed")?;

        let status_code = response.status();

        let body = response
            .bytes()
            .await
            .with_context(|| "service bridge response bad")?;

        if status_code != StatusCode::OK {
            return Err(anyhow!(
                "service bridge returned HTTP {} ({:?})",
                status_code.as_u16(),
                String::from_utf8(body.to_vec())
            ))?;
        }

        Ok(Message::decode(body)?)
    }

    fn api_url(&self) -> String {
        let mut host = "appengine.googleapis.internal".to_string();
        let mut port = "10001".to_string();

        if let Ok(h) = std::env::var("API_HOST") {
            host = h;
        }
        if let Ok(p) = std::env::var("API_PORT") {
            port = p;
        }

        format!("http://{}:{}/rpc_http", host, port)
    }
}

#[async_trait::async_trait]
impl CryptoSigner for AppEngineSigner {
    fn algorithm(&self) -> String {
        ALGORITHM_RS256.to_string()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let request = app_engine_grpc::SignForAppRequest {
            bytes_to_sign: Some(data.to_vec()),
        };

        let response: app_engine_grpc::SignForAppResponse = self
            .call("app_identity_service", "SignForApp", request)
            .await?;

        Ok(response.signature_bytes.unwrap())
    }

    async fn email(&self) -> Result<String> {
        let request = app_engine_grpc::GetServiceAccountNameRequest {};

        let response: app_engine_grpc::GetServiceAccountNameResponse = self
            .call("app_identity_service", "GetServiceAccountName", request)
            .await?;

        Ok(response.service_account_name.unwrap())
    }
}
