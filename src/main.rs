use oauth2::ExtraTokenFields;
impl ExtraTokenFields for IdTokenFields {}
// no need for hyper::Server import
use anyhow::Result;
use askama::Template;
use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::{header::SET_COOKIE, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::CookieJar;
// use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tracing;
use tracing_subscriber;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TodoItem {
    id: Uuid,
    title: String,
    completed: bool,
    user_sub: String, // user identifier from JWT
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
        let claims = validate_jwt(&token).map_err(|_| Redirect::to("/login").into_response())?;
        Ok(AuthUser {
            sub: claims.sub,
            name: claims.name,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    name: Option<String>,
    exp: usize,
}

fn validate_jwt(token: &str) -> Result<Claims> {
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
    validation.set_audience(&[CLIENT_ID]);
    let token_data: TokenData<Claims> = decode(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

// --- Keycloak OAuth2 config ---
static AUTH_URL: &str = "http://localhost:8080/realms/todo-realm/protocol/openid-connect/auth";
static TOKEN_URL: &str = "http://localhost:8080/realms/todo-realm/protocol/openid-connect/token";
static CLIENT_ID: &str = "todo-client";
static CLIENT_SECRET: &str = "18fYgnYsWEZIcDAQTb4vBdLjdcLdMidS";
static REDIRECT_URL: &str = "http://localhost:3000/callback";

static JWKS_URL: &str = "http://localhost:8080/realms/todo-realm/protocol/openid-connect/certs";

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

static JWKS: Lazy<HashMap<String, Jwk>> = Lazy::new(|| get_jwks());

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
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    Redirect::to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: Option<String>,
}

async fn callback(Query(params): Query<AuthRequest>) -> impl IntoResponse {
    let client = oauth_client();
    tracing::info!(?params, "Handling /callback with params");
    let token_result = client
        .exchange_code(AuthorizationCode::new(params.code.clone()))
        .request_async(async_http_client)
        .await;
    match &token_result {
        Ok(token) => {
            tracing::info!(?token, "Token exchange successful");
            // Convert token to JSON and back to get extra fields
            let token: oauth2::StandardTokenResponse<IdTokenFields, oauth2::basic::BasicTokenType> =
                serde_json::from_value(serde_json::to_value(&token).unwrap()).unwrap();
            let id_token = token.extra_fields().id_token.as_deref().unwrap_or("");
            tracing::info!(id_token = %id_token, "Extracted id_token from token response");
            let cookie = format!("auth_token={}; Path=/; HttpOnly", id_token);
            ([(SET_COOKIE, cookie)], Redirect::to("/")).into_response()
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
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().append(
        axum::http::header::SET_COOKIE,
        "auth_token=; Path=/; Max-Age=0".parse().unwrap(),
    );
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
    Redirect::to("/")
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
    Redirect::to("/")
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
    Redirect::to("/")
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let todos: TodoList = Arc::new(Mutex::new(load_todos()));
    let app = Router::new()
        .route("/", get(index))
        .route("/add", post(add_todo))
        .route("/toggle/:id", post(toggle_todo))
        .route("/delete/:id", post(delete_todo))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .with_state(todos);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    // Note: hyper is the underlying server for axum 0.7
}
