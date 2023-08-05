use actix_web::{web, App, HttpServer, get, post, Responder};
use serde::{Serialize, Deserialize};
use tokio_postgres::{NoTls, Client, GenericClient};
use deadpool_postgres::{Pool, Manager, RecyclingMethod, ManagerConfig};

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
async fn register(data: web::Json<RegisterRequest>, client: web::Data<Pool>) -> web::Json<AuthResult> {

    let credentials = crate::auth::hash_password(&data.password);

    /// TODO: create user in database if not exist else thorw error
    /// TODO: create refresh token in database

    match client.get().await.unwrap().query(
        "INSERT INTO users (username, password, email) VALUES ($1, $2, $3)",
        &[&data.username, &credentials.hash, &data.email]
    ).await {
        Ok(_) => println!("User created"),
        Err(e) => println!("Error creating user: {}", e)
    }

    web::Json(AuthResult {
        token: create_token(),
        refresh_token: "NOT_IMPLEMENTED".to_string(),
        expires_in: 3600,
    })
}

#[post("/login")]
async fn login() -> impl Responder {
    // panic!("Not implemented")
    "Hello world!"
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
async fn main() -> std::io::Result<()> {
    let mut pg_config = tokio_postgres::Config::new();
    pg_config.user("postgres");
    pg_config.password("postgres");
    pg_config.dbname("postgres");
    pg_config.port(5433);
    pg_config.host("localhost");

    let manager = Manager::new(pg_config, NoTls).await.unwrap();
    let pool = Pool::new(manager, 10, RecyclingMethod::Fast);

    HttpServer::new(|| {
        App::new()
            .app_data(pool.clone())
            .service(register)
    })
    .bind("0.0.0.0:8075")?
    .run()
    .await
}
