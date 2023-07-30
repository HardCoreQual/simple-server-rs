use actix_web::{web, App, HttpServer, get, post};
use serde::{Serialize, Deserialize};

use crate::auth::{hash_password, create_token};

mod auth;

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
}

struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResult {
    token: String,
    refresh_token: String,
    expires_in: i32,
}

#[post("/register")]
async fn register(data: web::Json<RegisterRequest>) -> web::Json<AuthResult> {

    let credentials = crate::auth::hash_password(&data.password);

    /// TODO: create user in database if not exist else thorw error
    /// TODO: create refresh token in database

    web::Json(AuthResult {
        token: create_token(),
        refresh_token: "NOT_IMPLEMENTED".to_string(),
        expires_in: 3600,
    })
}

#[post("/login")]
async fn login() -> String {
    panic!("Not implemented")
}

#[post("/refresh_token")]
async fn refresh_token() -> String {
    panic!("Not implemented")
}

#[post("/profile?id={id}")]
async fn profile() -> String {
    panic!("Not implemented")
}


#[tokio::main]
async fn main() {
    HttpServer::new(|| {
        App::new()
            .service(register)
    })
    .bind("0.0.0.0:8075")
    .unwrap()
    .run()
    .await
    .unwrap();
}
