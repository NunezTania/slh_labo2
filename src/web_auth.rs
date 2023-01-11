use crate::db::{DbConn, save_user, user_exists, set_verified, get_user, update_password};
use crate::models::{AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest};
use crate::user::{AuthenticationMethod, User, UserDTO};
use serde::{Deserialize, Serialize};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, SessionStore, Session};
use serde_json::json;
use std::error::Error;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::env;
use time::{Duration, OffsetDateTime};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum_sessions::async_session::chrono::Utc;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use oauth2::reqwest::async_http_client;
use crate::oauth::get_google_oauth_email;

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .route("/verify/:token", get(verify))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    // TODO: Implement the login function. You can use the functions inside db.rs to check if
    //       the user exists and get the user info.
    let _email = login.login_email;
    let _password = login.login_password;

    // Vérifier que le user est valide
    let user = match get_user(&mut _conn, _email.to_lowercase().as_str()) {
        Ok(user) => user,
        Err(_) => return Err(AuthResult::UserNotFound.into_response()),
    };
    // Vérifier que l'email a été validé
    if !user.email_verified {
        return Err(AuthResult::UnverifiedEmail.into_response());
    }
    // Récupérer le mot de passe hashé
    let hashed_pwd = match PasswordHash::new(&user.password) {
        Ok(hashed_pwd) => hashed_pwd,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    };

    // Vérifier que l'utilisateur s'authentifie avec le bon moyen
    match user.get_auth_method() {
        AuthenticationMethod::Password => {
            // Vérifier que le mot de passe est correct
            Argon2::default().verify_password(_password.as_str().as_ref(), &hashed_pwd)
                .or(Err(AuthResult::InvalidCredentials.into_response()))?;
        }
        AuthenticationMethod::OAuth => {
            return Err(AuthResult::InvalidAuthenticationMethod.into_response());
        }
    }

    // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
    let jar = add_auth_cookie(jar, &user.to_dto())
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
    Ok((jar, AuthResult::Success))
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the register function. The email must be verified by sending a link.
    //       You can use the functions inside db.rs to add a new user to the DB.
    let _email = register.register_email;
    let _password = register.register_password;
    let _password2 = register.register_password2;

    let email_slice = &(_email.to_owned());
    let password_slice = &(_password.to_owned());

    // Vérifier que les deux mots de passe sont identiques
    if _password != _password2 {
        return Err(AuthResult::PasswordsDontMatch.into_response());
    }

    // Verifier la longueur du mot de passe (entre 8 et 64 caractères)
    let length = password_slice.chars().count();
    if length < 8 || length > 64 {
        return Err(AuthResult::WrongPasswordLength.into_response());
    }

    // Vérifier la force du mot de passe
    let strength = zxcvbn::zxcvbn(password_slice, &[email_slice])
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    if strength.score() < 3 {
        return Err(AuthResult::WeakPassword.into_response());
    }

    // Hash le mot de passe avec du sel
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(_password.as_ref(), salt.as_ref())
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    // Vérifie que le user n'existe pas déjà
    match user_exists(&mut _conn, email_slice) {
        Ok(_) => return Err(AuthResult::UserAlreadyExists.into_response()),
        Err(_) => {}
    }

    // Créer le user
    let user = User::new(email_slice, hash.to_string().as_str(), AuthenticationMethod::Password, false);
    save_user(&mut _conn, user).or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;


    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    let mut session = Session::new();
    session.insert("email", email_slice.clone().to_string()).or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
    let session_id = _session_store.store_session(session).await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

    // Once the user has been created, send a verification link by email
    let mut verification_link = "http://localhost:8000/verify/".to_owned();
    url_escape::encode_component_to_string(session_id.unwrap(), &mut verification_link);
    send_verification_mail(email_slice, &verification_link);

    return Ok(AuthResult::Success);
}

fn send_verification_mail(email : &str, verification_link : &str) {

    let verification_email = Message::builder()
        .from("noreply@localhost".parse().unwrap())
        .to(email.clone().parse().unwrap())
        .subject("Verify your email")
        .body(verification_link.to_string())
        .unwrap();

    let creds = Credentials::new(env::var("SMTP_USERNAME").unwrap().to_string(),
                                 env::var("SMTP_PASSWORD").unwrap().to_string());
    // Ici nous utilisons une configuration pour utiliser mailtrap d'où l'utilisation de builder_dangerous
    // Toute la configuration inhérente à l'envoi du mail se trouve dans le fichier .env
    let mailer = SmtpTransport::builder_dangerous(env::var("SMTP_HOST").unwrap().as_str())
        .credentials(creds)
        .port(env::var("SMTP_PORT").unwrap().parse::<u16>().expect("SMTP_PORT must be a number"))
        .build();

    match mailer.send(&verification_email) {
        Ok(_) => println!("Email sent"),
        Err(e) => println!("Could not send email: {}", e),
    }
}

// TODO: Create the endpoint for the email verification function.
async fn verify(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Path(session_id_encoded) : Path<String>
) -> Redirect {
    // Récupération de l'id de session dans laquelle nous avons précédemment mis l'email (via le
    // Path du lien de vérification)
    let session_id = url_escape::decode(session_id_encoded.as_str()).to_string();
    let session = match get_session(&session_id, &_session_store).await {
        Some(s) => s,
        None => return Redirect::to("/login")
    };
    let email : String = match session.get::<String>("email") {
        Some(e) => e.to_string(),
        None => return Redirect::to("/login")
    };

    match set_verified(&mut _conn, email.as_str()) {
        Ok(_) => {},
        Err(_) => return Redirect::to("/login")
    }
    match _session_store.destroy_session(session).await {
        Ok(_) => {},
        Err(_) => return Redirect::to("/login")
    };
    Redirect::to("/login")
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.


    let client = &crate::oauth::OAUTH_CLIENT;

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    let mut session = Session::new();
    session.insert("pkce_verifier", pkce_verifier.secret()).unwrap();
    session.insert("csrf_token", csrf_token.secret()).unwrap();
    let session_id = _session_store.store_session(session).await
        .unwrap();
    let cookie = Cookie::build("session_id", session_id.unwrap())
        .expires(OffsetDateTime::now_utc() + Duration::hours(1))
        .http_only(true)
        .path("/")
        .finish();
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    Ok((jar.add(cookie), Redirect::to(auth_url.as_str())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    let session_id = jar.get("session_id").unwrap().value().to_string();
    let csrf_token_param = _params.state.clone();

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.
    let session = match get_session(&session_id, &_session_store).await {
        Some(s) => s,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR)
    };
    let pkce_verifier = match session.get::<String>("pkce_verifier") {
        Some(v) => v,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR)
    };
    let csrf_token = match session.get::<String>("csrf_token") {
        Some(t) => t,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR)
    };

    if csrf_token_param != csrf_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let client = &crate::oauth::OAUTH_CLIENT;

    let token_result = match client
        .exchange_code(AuthorizationCode::new(_params.code.to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request_async(async_http_client)
        .await {
                    Ok(token) => token,
                    Err(err) => {
                        println!("Error: {}", err);
                        return Err(StatusCode::UNAUTHORIZED);
                    }
        };

    let email = match get_google_oauth_email(&token_result).await {
        Ok(email) => email,
        Err(err) => {
            println!("Error: {}", err);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };


    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    let user = User::new(email.as_str(), "",AuthenticationMethod::OAuth, true);
    match user_exists(&mut _conn, user.email.as_str()) {
        Ok(_) => return Err(StatusCode::BAD_REQUEST),
        Err(_) => {}
    }
    match save_user(&mut _conn, user.clone()) {
        Ok(_) => println!("User saved"),
        Err(e) => println!("Could not save user: {}", e),
    }
    let jar = add_auth_cookie(jar, &user.to_dto()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the password update function.
    let _password = _update.old_password;
    let _new_password = _update.new_password;

    let user = get_user(&mut _conn, _user.email.to_lowercase().as_str())
        .or(Err(AuthResult::UserNotFound.into_response()))
        .unwrap();

    let hashed_pwd = PasswordHash::new(&user.password).
        or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        .unwrap();

    match _user.auth_method {
        AuthenticationMethod::Password => {
            // Vérifier que le mot de passe est correct
            Argon2::default().verify_password(_password.as_str().as_ref(), &hashed_pwd)
                .or(Err(AuthResult::InvalidCredentials.into_response()))?;

            // Changer le mot de passe

            // Verifier la longueur du mot de passe (entre 8 et 64 caractères)
            let length = _password.as_str().chars().count();
            if length < 8 || length > 64 {
                return Err(AuthResult::WrongPasswordLength.into_response());
            }

            // Vérifier la force du mot de passe
            let strength = zxcvbn::zxcvbn(_password.as_str(), &[_user.email.as_str()])
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

            if strength.score() < 3 {
                return Err(AuthResult::WeakPassword.into_response());
            }
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hash = argon2.hash_password(_new_password.as_ref(), salt.as_ref())
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
            update_password(&mut _conn, _user.email.as_str(), hash.to_string().as_ref())
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
        }
        AuthenticationMethod::OAuth => {
            return Err(AuthResult::InvalidAuthenticationMethod.into_response());
        }
    }
    Ok(AuthResult::Success)
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    // TODO: You have to create a new signed JWT and store it in the auth cookie.
    //       Careful with the cookie options.
    let secret = env::var("SECRET_KEY")
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        .unwrap();

    let expiration = env::var("COOKIE_EXPIRATION")
        .expect("COOKIE_EXPIRATION must be set")
        .parse::<i64>()
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        .unwrap();

    let jwt_payload = JWTPayload {
        sub: _user.email.clone(),
        auth: _user.auth_method.clone(),
        exp: Utc::now().timestamp() + expiration,
    };
    let token = encode(&Header::default(), &jwt_payload,
                       &EncodingKey::from_secret(secret.as_ref()))?;

    let cookie = Cookie::build("auth", token)
        .expires(OffsetDateTime::now_utc() + Duration::days(expiration))
        .http_only(true)
        .path("/")
        .finish();

    Ok(jar.add(cookie))
}

async fn get_session(session_id : &String, session_store: &MemoryStore) -> Option<Session> {
    match session_store.load_session(session_id.to_string()).await {
        Ok(session) => session,
        Err(err) => {
            println!("Error while getting session: {}", err);
            None
        }
    }
}

enum AuthResult {
    Success,
    WrongPasswordLength,
    WeakPassword,
    PasswordsDontMatch,
    UserAlreadyExists,
    UserNotFound,
    InvalidAuthenticationMethod,
    InvalidCredentials,
    UnverifiedEmail,
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::WrongPasswordLength => (StatusCode::BAD_REQUEST, "Password must be at least 8 characters long and less than 64 caracters long"),
            Self::WeakPassword => (StatusCode::BAD_REQUEST, "Password is too weak, try adding special caracters and remove previous inputs copies"),
            Self::UserAlreadyExists => (StatusCode::BAD_REQUEST, "User already exists"),
            Self::UserNotFound => (StatusCode::BAD_REQUEST, "User not found"),
            Self::InvalidAuthenticationMethod => (StatusCode::BAD_REQUEST, "Invalid authentication method"),
            Self::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            Self::UnverifiedEmail => (StatusCode::BAD_REQUEST, "Email not verified"),
            Self::PasswordsDontMatch => (StatusCode::BAD_REQUEST, "Passwords don't match"),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct JWTPayload {
    pub sub : String,
    pub auth : AuthenticationMethod,
    exp : i64,
}
