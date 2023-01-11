use std::env;
use crate::db::Pool;
use crate::user::UserDTO;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::web_auth::JWTPayload;

const REDIRECT_URL: &str = "/home";

/// Retrieves a UserDTO from request parts if a user is currently authenticated.
#[async_trait]
impl<S> FromRequestParts<S> for UserDTO
where
    Pool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // TODO: You have to read the auth cookie and verify the JWT to ensure the user is
        //       authenticated.

        let jar = parts
            .extract::<CookieJar>()
            .await
            .expect("Could not get CookieJar from request parts");
        let _jwt = jar.get("auth").ok_or(Redirect::to(REDIRECT_URL))?.value();

        let secret = env::var("SECRET_KEY").expect("SECRET must be set");
        // Décodage du token à l'aide de la struct JWTPayload pour avoir un champs sub et exp
        // Si ces derniers ne sont pas présent dans la struct, une erreur se produit
        match decode::<JWTPayload>(&_jwt,
                                   &DecodingKey::from_secret(secret.as_ref()),
                                   &Validation::default()) {
            Ok(token) => {
                let user = UserDTO {
                    email: token.claims.sub,
                    auth_method: token.claims.auth,
                };
                Ok(user)
            }
            Err(e) => {
                println!("Error decoding token : {}", e);
                Err(Redirect::to(REDIRECT_URL))
            }
        }
    }
}
