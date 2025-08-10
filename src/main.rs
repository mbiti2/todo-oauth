use anyhow::Result;
use askama::Template;
use axum::http::{header::SET_COOKIE, HeaderValue, Method};
use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::CookieJar;
use chrono;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use oauth2::ExtraTokenFields;
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use once_cell::sync::Lazy;
use reqwest;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing;
use tracing_subscriber;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TodoItem {
    id: Uuid,
    title: String,
    completed: bool,
    user_sub: String,
}

type TodoList = Arc<Mutex<Vec<TodoItem>>>;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    todos: &'a [TodoItem],
}

#[derive(Deserialize)]
struct NewTodo {
    title: String,
}

struct AuthUser {
    sub: String,
    name: Option<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get("auth_token")
            .map(|c| c.value().to_string())
            .ok_or_else(|| Redirect::to("/login").into_response())?;
        match validate_jwt(&token).await {
            Ok(claims) => Ok(AuthUser {
                sub: claims.sub,
                name: claims.name,
            }),
            Err(err) => {
                tracing::error!(error = %err, "Failed to validate token; returning 401 to avoid redirect loop");
                let body =
                    Html("<p>Authentication required.</p><p><a href=\"/login\">Login</a></p>");
                Err((StatusCode::UNAUTHORIZED, body).into_response())
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
    name: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    nbf: Option<usize>,
}

async fn validate_jwt(token: &str) -> Result<Claims> {
    if let Ok(claims) = fetch_user_info_via_introspection(token).await {
        return Ok(claims);
    }
    if let Ok(claims) = fetch_user_info_from_access_token(token).await {
        return Ok(claims);
    }
    match try_validate_as_jwt(token) {
        Ok(claims) => {
            let now = chrono::Utc::now().timestamp() as usize;
            if claims.exp <= now {
                tracing::error!("Token has expired");
                return Err(anyhow::anyhow!("Token expired"));
            }
            Ok(claims)
        }
        Err(e) => Err(e),
    }
}

fn try_validate_as_jwt(token: &str) -> Result<Claims> {
    let header = decode_header(token)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("No kid in header"))?;
    let jwks = get_jwks();
    let jwk = jwks
        .get(&kid)
        .ok_or_else(|| anyhow::anyhow!("No matching JWK"))?;
    let decoding_key =
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| anyhow::anyhow!(e))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60;

    let token_data: TokenData<Claims> = decode(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

async fn fetch_user_info_from_access_token(access_token: &str) -> Result<Claims> {
    let client = reqwest::Client::new();

    let response = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch user info: {}",
            response.status()
        ));
    }

    let user_info: serde_json::Value = response.json().await?;
    tracing::info!(?user_info, "Fetched user info from access token");

    let now = chrono::Utc::now().timestamp() as usize;
    Ok(Claims {
        sub: user_info["sub"].as_str().unwrap_or("").to_string(),
        exp: now + 300,
        iat: now,
        iss: ISSUER.to_string(),
        aud: CLIENT_ID.to_string(),
        name: user_info["name"].as_str().map(|s| s.to_string()),
        preferred_username: user_info["preferred_username"]
            .as_str()
            .map(|s| s.to_string()),
        email: user_info["email"].as_str().map(|s| s.to_string()),
        nbf: Some(now),
    })
}

async fn fetch_user_info_via_introspection(access_token: &str) -> Result<Claims> {
    let client = reqwest::Client::new();
    let params = [
        ("token", access_token),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
    ];
    let resp = client.post(INTROSPECT_URL).form(&params).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Introspection failed: {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await?;
    if !v["active"].as_bool().unwrap_or(false) {
        return Err(anyhow::anyhow!("Token inactive"));
    }
    let now = chrono::Utc::now().timestamp() as usize;
    Ok(Claims {
        sub: v["sub"].as_str().unwrap_or("").to_string(),
        exp: v["exp"].as_u64().map(|u| u as usize).unwrap_or(now + 300),
        iat: v["iat"].as_u64().map(|u| u as usize).unwrap_or(now),
        iss: v["iss"].as_str().unwrap_or(ISSUER).to_string(),
        aud: v["aud"].as_str().unwrap_or(CLIENT_ID).to_string(),
        name: v["name"].as_str().map(|s| s.to_string()),
        preferred_username: v["preferred_username"].as_str().map(|s| s.to_string()),
        email: v["email"].as_str().map(|s| s.to_string()),
        nbf: v["nbf"].as_u64().map(|u| u as usize),
    })
}

static REALM: &str = "todo-realm";
static CLIENT_ID: &str = "todo-client";
static CLIENT_SECRET: &str = "18fYgnYsWEZIcDAQTb4vBdLjdcLdMidS";
static AUTH_URL: &str = "http://localhost:8080/realms/todo-realm/protocol/openid-connect/auth";
static REDIRECT_URL: &str = "http://localhost:3000/callback";
static INTERNAL_BASE_URL: &str = "http://keycloak:8080";
static TOKEN_URL: &str = "http://keycloak:8080/realms/todo-realm/protocol/openid-connect/token";
static JWKS_URL: &str = "http://keycloak:8080/realms/todo-realm/protocol/openid-connect/certs";
static USERINFO_URL: &str =
    "http://keycloak:8080/realms/todo-realm/protocol/openid-connect/userinfo";
static ISSUER: &str = "http://localhost:8080/realms/todo-realm";
static INTROSPECT_URL: &str =
    "http://keycloak:8080/realms/todo-realm/protocol/openid-connect/token/introspect";

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

static JWKS: Lazy<HashMap<String, Jwk>> = Lazy::new(|| get_jwks());

static PKCE_VERIFIERS: Lazy<Arc<Mutex<HashMap<String, PkceCodeVerifier>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

fn get_jwks() -> HashMap<String, Jwk> {
    let resp = reqwest::blocking::get(JWKS_URL).unwrap();
    let jwks_json: serde_json::Value = resp.json().unwrap();
    let mut map = HashMap::new();
    for jwk in jwks_json["keys"].as_array().unwrap() {
        let kid = jwk["kid"].as_str().unwrap().to_string();
        let n = jwk["n"].as_str().unwrap().to_string();
        let e = jwk["e"].as_str().unwrap().to_string();
        map.insert(kid.clone(), Jwk { kid, n, e });
    }
    map
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct IdTokenFields {
    id_token: Option<String>,
}

impl ExtraTokenFields for IdTokenFields {}

fn oauth_client() -> BasicClient {
    BasicClient::new(
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
        AuthUrl::new(AUTH_URL.to_string()).unwrap(),
        Some(TokenUrl::new(TOKEN_URL.to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URL.to_string()).unwrap())
}

async fn login() -> impl IntoResponse {
    let client = oauth_client();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    {
        let mut verifiers = PKCE_VERIFIERS.lock().await;
        verifiers.insert(csrf_token.secret().clone(), pkce_verifier);
    }

    Redirect::to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: Option<String>,
}

async fn callback(jar: CookieJar, Query(params): Query<AuthRequest>) -> impl IntoResponse {
    let client = oauth_client();
    tracing::info!(?params, "Handling /callback with params");

    let state = match params.state.as_ref() {
        Some(state) => state.clone(),
        None => {
            if jar.get("auth_token").is_some() {
                return Redirect::to("/").into_response();
            }
            tracing::error!("Missing state parameter in callback");
            return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response();
        }
    };

    let pkce_verifier = {
        let mut verifiers = PKCE_VERIFIERS.lock().await;
        match verifiers.remove(&state) {
            Some(verifier) => verifier,
            None => {
                if jar.get("auth_token").is_some() {
                    return Redirect::to("/").into_response();
                }
                tracing::error!("PKCE verifier not found for state: {:?}", params.state);
                return (StatusCode::BAD_REQUEST, "Invalid state parameter").into_response();
            }
        }
    };

    let token_result = client
        .exchange_code(AuthorizationCode::new(params.code.clone()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await;
    match &token_result {
        Ok(token) => {
            tracing::info!(?token, "Token exchange successful");
            let token_with_extra: oauth2::StandardTokenResponse<
                IdTokenFields,
                oauth2::basic::BasicTokenType,
            > = serde_json::from_value(serde_json::to_value(&token).unwrap()).unwrap();
            let id_token_opt = token_with_extra.extra_fields().id_token.clone();
            let token_for_cookie = match id_token_opt {
                Some(ref s) if !s.is_empty() => s.clone(),
                _ => token.access_token().secret().to_string(),
            };
            tracing::info!(have_id_token = %id_token_opt.is_some(), "Choosing token for cookie");
            {
                let mut verifiers = PKCE_VERIFIERS.lock().await;
                verifiers.remove(&state);
            }

            let exp = chrono::Utc::now() + chrono::Duration::minutes(30);
            let cookie = format!(
                "auth_token={}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=1800; Expires={}",
                token_for_cookie,
                exp.format("%a, %d %b %Y %H:%M:%S GMT")
            );

            let mut response = Redirect::to("/todos").into_response();
            response
                .headers_mut()
                .append(SET_COOKIE, cookie.parse().unwrap());

            if let Some(refresh_token) = token.refresh_token() {
                let refresh_cookie = format!(
                    "refresh_token={}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=86400; Expires={}",
                    refresh_token.secret(),
                    (exp + chrono::Duration::days(1)).format("%a, %d %b %Y %H:%M:%S GMT")
                );
                response
                    .headers_mut()
                    .append(SET_COOKIE, refresh_cookie.parse().unwrap());
            }

            response
        }
        Err(e) => {
            tracing::error!(error = %e, code = ?params.code, "Failed to exchange code for token");
            (
                StatusCode::UNAUTHORIZED,
                format!("Failed to exchange code for token: {e}"),
            )
                .into_response()
        }
    }
}

async fn logout() -> impl IntoResponse {
    let post_logout_redirect = "http%3A%2F%2Flocalhost%3A3000%2Flogin";
    let end_session = format!(
        "{issuer}/protocol/openid-connect/logout?client_id={client_id}&post_logout_redirect_uri={redir}",
        issuer = ISSUER,
        client_id = CLIENT_ID,
        redir = post_logout_redirect
    );

    let mut resp = Redirect::to(&end_session).into_response();

    let cookies = [
        "auth_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "refresh_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ];

    for cookie in cookies {
        resp.headers_mut()
            .append(SET_COOKIE, cookie.parse().unwrap());
    }

    resp
}

#[axum::debug_handler]
async fn index(
    axum::extract::State(todos): axum::extract::State<TodoList>,
    user: AuthUser,
) -> impl IntoResponse {
    let todos = todos.lock().await;
    let user_todos: Vec<_> = todos
        .iter()
        .filter(|t| t.user_sub == user.sub)
        .cloned()
        .collect();
    let html = IndexTemplate { todos: &user_todos }.render().unwrap();
    Html(html)
}

#[axum::debug_handler]
async fn add_todo(
    axum::extract::State(todos): axum::extract::State<TodoList>,
    user: AuthUser,
    axum::extract::Form(input): axum::extract::Form<NewTodo>,
) -> impl IntoResponse {
    let mut todos = todos.lock().await;
    let todo = TodoItem {
        id: Uuid::new_v4(),
        title: input.title,
        completed: false,
        user_sub: user.sub,
    };
    todos.push(todo);
    save_todos(&todos);
    Redirect::to("/todos")
}

#[axum::debug_handler]
async fn toggle_todo(
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    axum::extract::State(todos): axum::extract::State<TodoList>,
    user: AuthUser,
) -> impl IntoResponse {
    let mut todos = todos.lock().await;
    if let Some(todo) = todos
        .iter_mut()
        .find(|t| t.id == id && t.user_sub == user.sub)
    {
        todo.completed = !todo.completed;
    }
    save_todos(&todos);
    Redirect::to("/todos")
}

#[axum::debug_handler]
async fn delete_todo(
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    axum::extract::State(todos): axum::extract::State<TodoList>,
    user: AuthUser,
) -> impl IntoResponse {
    let mut todos = todos.lock().await;
    todos.retain(|t| !(t.id == id && t.user_sub == user.sub));
    save_todos(&todos);
    Redirect::to("/todos")
}

fn save_todos(todos: &Vec<TodoItem>) {
    let data = serde_json::to_string_pretty(todos).unwrap();
    fs::write("todos.json", data).unwrap();
}

fn load_todos() -> Vec<TodoItem> {
    fs::read_to_string("todos.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(Vec::new)
}

#[derive(Template)]
#[template(path = "landing.html")]
struct LandingTemplate;

async fn landing_page() -> impl axum::response::IntoResponse {
    let html = LandingTemplate.render().unwrap();
    axum::response::Html(html)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let todos: TodoList = Arc::new(Mutex::new(load_todos()));

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::exact(
            "http://localhost:3000"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
        ))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
        axum::http::header::AUTHORIZATION,
        axum::http::header::CONTENT_TYPE,
        axum::http::header::ACCEPT,
    ])
        .allow_credentials(true);

    let app = Router::new()
        .route("/", get(landing_page))
        .route("/todos", get(index))
        .route("/add", post(add_todo))
        .route("/toggle/:id", post(toggle_todo))
        .route("/delete/:id", post(delete_todo))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .with_state(todos)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
