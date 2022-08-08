use serde::Deserialize;

#[derive(Deserialize)]
pub struct Tenant {
    #[serde(rename = "name")]
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "allowPasswordSignup")]
    pub allow_password_sign_up: bool,
    #[serde(rename = "enableEmailLinkSignin")]
    pub enable_email_link_sign_in: bool,
    #[serde(rename = "enableAnonymousUser")]
    pub enable_anonymous_users: bool,
}
