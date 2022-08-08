use super::json::JsonObject;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Firebase(#[from] FirebaseError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
pub(crate) enum FirebaseErrorCode {
    // InvalidArgument is a OnePlatform error code.
    InvalidArgument,

    // FailedPrecondition is a OnePlatform error code.
    FailedPrecondition,

    // OutOfRange is a OnePlatform error code.
    OutOfRange,

    // Unauthenticated is a OnePlatform error code.
    Unauthenticated,

    // PermissionDenied is a OnePlatform error code.
    PermissionDenied,

    // NotFound is a OnePlatform error code.
    NotFound,

    // Conflict is a custom error code that represents HTTP 409 responses.
    //
    // OnePlatform APIs typically respond with ABORTED or ALREADY_EXISTS explicitly. But a few
    // old APIs send HTTP 409 Conflict without any additional details to distinguish between the two
    // cases. For these we currently use this error code. As more APIs adopt OnePlatform conventions
    // this will become less important.
    Conflict,

    // Aborted is a OnePlatform error code.
    Aborted,

    // AlreadyExists is a OnePlatform error code.
    AlreadyExists,

    // ResourceExhausted is a OnePlatform error code.
    ResourceExhausted,

    // Cancelled is a OnePlatform error code.
    Cancelled,

    // DataLoss is a OnePlatform error code.
    DataLoss,

    // Unknown is a OnePlatform error code.
    Unknown,

    // Internal is a OnePlatform error code.
    Internal,

    // Unavailable is a OnePlatform error code.
    Unavailable,

    // DeadlineExceeded is a OnePlatform error code.
    DeadlineExceeded,
}

#[derive(Debug, thiserror::Error)]
#[error("{string}")]
pub struct FirebaseError {
    pub(crate) error_code: FirebaseErrorCode,
    pub(crate) string: String,
    pub(crate) ext: JsonObject,
}

macro_rules! impl_other_error {
    ($err:ty) => {
        impl From<$err> for Error {
            fn from(e: $err) -> Self {
                Self::Other(anyhow::Error::new(e))
            }
        }
    };
}

impl_other_error!(base64::DecodeError);
impl_other_error!(prost::DecodeError);
impl_other_error!(prost::EncodeError);
impl_other_error!(reqwest::Error);
impl_other_error!(reqwest::header::InvalidHeaderValue);
impl_other_error!(reqwest::header::ToStrError);
impl_other_error!(serde_json::Error);
impl_other_error!(signature::Error);
impl_other_error!(std::num::ParseIntError);
impl_other_error!(x509_certificate::X509CertificateError);
