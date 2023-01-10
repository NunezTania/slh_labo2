use std::env;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl};
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
/// Lazy is used to initialize a complex static variable as it is currently not supported in native Rust.
/// The initialization is done only once when the variable is used for the first time.  
pub static OAUTH_CLIENT: Lazy<BasicClient> = Lazy::new(|| {
    // TODO: We currently hardcode the credentials, try to improve it.
    let google_client_id = ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap());
    let google_client_secret = ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap());

    let auth_url = AuthUrl::new(env::var("GOOGLE_CLIENT_AUTH_URL").unwrap())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new(env::var("GOOGLE_CLIENT_TOKEN_URL").unwrap())
        .expect("Invalid token endpoint URL");

    // TODO: Set redirect URI, be careful to use the same as the one configured in Google Cloud.
    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new(env::var("GOOGLE_CLIENT_REDIRECT_URI").unwrap()).expect("Invalid redirect URL"),
    )
});

#[allow(dead_code)]
static REQW_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| reqwest::Client::new());

/// Structure returned by Google API when requesting the email address
#[derive(Serialize, Deserialize, Debug)]
struct UserInfoEmail {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

#[allow(dead_code)]
/// Returns the email address associated with the token
pub async fn get_google_oauth_email(token: &BasicTokenResponse) -> Result<String, StatusCode> {
    REQW_CLIENT
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .query(&[("access_token", token.access_token().secret())])
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .await
        .and_then(|r| Ok(r.json::<UserInfoEmail>()))
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))?
        .await
        .and_then(|user_info| Ok(user_info.email))
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))
}
