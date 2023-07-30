use std::num::NonZeroU32;
use ring::{digest, pbkdf2};
use rand::Rng;
use rand::rngs::OsRng;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Mutex, Arc};
use lazy_static::lazy_static;


use data_encoding::{BASE64, DecodeError};


const CREDENTIALS_LENGTH: usize = digest::SHA512_OUTPUT_LEN;
type Hash = [u8; CREDENTIALS_LENGTH];

pub struct Credentials {
    hash: String,
    salt: String,
}

pub fn hash_password(password: &str) -> Credentials {
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let salt = generate_salt();
    let mut credential = [0u8; CREDENTIALS_LENGTH];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt,
        password.as_bytes(),
        &mut credential,
    );

    Credentials {
        hash: BASE64.encode(&credential),
        salt: BASE64.encode(&salt),
    }
}

pub fn verify_password(
    hashed_password: &Credentials,
    password: &str,
) -> bool {
    let n_iter = NonZeroU32::new(100_000).unwrap();
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        hashed_password.salt.as_bytes(),
        password.as_bytes(),
        hashed_password.hash.as_bytes(),
    )
    .is_ok()
}

fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill(&mut salt[..]);
    salt
}

pub fn create_token() -> String {
    let secret = get_config().lock().unwrap().token_secret.clone();

    let exp = get_current_time() + 15 * 60;

     encode(&Header::default(), &TokenData { exp }, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

pub fn verify_token(token: &str) -> bool {
    let secret = get_config().lock().unwrap().token_secret.clone();

    let token_data: TokenData = decode(token, &DecodingKey::from_secret(secret.as_ref()), &Default::default()).unwrap().claims;

    let now = get_current_time();

    token_data.exp > now
}


fn get_current_time() -> u64 {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs()
}



#[derive(Serialize, Deserialize)]
struct TokenData {
    exp: u64,
}



pub struct Config {
    pub token_secret: String,
}


lazy_static! {
    static ref SINGLETON_CONFIG: Arc<Mutex<Config>> = {
        let token_secret = std::env::var("TOKEN_SECRET").unwrap_or("".to_string());
        Arc::new(Mutex::new(Config { token_secret }))
    };
}

pub fn get_config() -> Arc<Mutex<Config>> {
    Arc::clone(&*SINGLETON_CONFIG)
}