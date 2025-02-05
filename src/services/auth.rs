use std::{future::Future, pin::Pin};

use actix_web::{get, web::{self, Payload}, FromRequest, HttpRequest, HttpResponse, Responder, error::{ErrorUnauthorized, Error}};
use jsonwebtoken::{encode,decode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // Subject (typically the user ID or email)
    pub exp: usize, // 过期时间
                     // Add other claims as needed (e.g., exp, iat, etc.)
}

impl FromRequest for Claims {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_str| {
                    if auth_str.starts_with("Bearer ") {
                        Some(auth_str[7..].to_string())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    ErrorUnauthorized(json!({
                        "error": "Missing or invalid authorization header"
                    }))
                })?;

            // let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
            let secret = "your-secret-key".to_string();
            println!("secret: {}", secret);
            println!("token: {}", token);

            let token_data: jsonwebtoken::TokenData<Claims> = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::default()
            ).map_err(|_| {
                ErrorUnauthorized(json!({
                    "error": "Invalid token"
                }))
            })?;

            Ok(Claims {
                sub: token_data.claims.sub.clone(),
                exp: token_data.claims.exp,
            })
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthRes {
    email: String, // Subject (typically the user ID or email)
    access_token: String,
    jwt_token: String, // Add other claims as needed (e.g., exp, iat, etc.)
}

#[derive(Deserialize)]
struct AuthCode {
    code: String,
}

#[derive(Deserialize)]
struct GithubUser {
    email: String,
    primary: bool,
    verified: bool,
    visibility: Option<String>, // visibility 可以为空
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    // 可能会有其他的字段，根据GitHub的响应进行调整
}

async fn exchange_code_for_token(code: &str) -> Result<AuthRes, reqwest::Error> {
    // let client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    //    let client_secret = env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set");
    let client_id = String::from("Ov23lix14xI8yCaYz8cP");
    let client_secret = String::from("f9e73e5bf1d3f774b35cc78515bf07dfbf26aba0");

    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code.to_string()),
    ];

    let client = Client::new();
    let response = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await?;

    let result: AccessTokenResponse = response.json().await?;

    //  获取用户信息 (需要 User-Agent 头)
    let client = Client::new();
    let user_email_res = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(&result.access_token)
        .header("User-Agent", "my-app") // 设置 User-Agent
        .send()
        .await?;
    let user_email_arr: Vec<GithubUser> = user_email_res.json().await?;
    let primary_email = user_email_arr.iter().find(|email| email.primary);

    let my_claims = Claims {
        sub: primary_email.unwrap().email.clone(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
    };

    let key = EncodingKey::from_secret("your-secret-key".as_ref()); // Replace with your secret key

    let token = encode(&Header::default(), &my_claims, &key).unwrap();


    let res  = decode::<Claims>(&token, &DecodingKey::from_secret("your-secret-key".as_ref()), &Validation::default()).unwrap();
    println!("res: {:?}", res);

    // println!("JWT: {}", token);
    // println!("{:?}", user_email_res.text().await);
    let auth_res = AuthRes {
        email: primary_email.unwrap().email.clone(),
        access_token: result.access_token,
        jwt_token: token,
    };

    Ok(auth_res)
}

#[get("/auth/github/callback")]
pub async fn github_callback(query: web::Query<AuthCode>, _req: HttpRequest) -> impl Responder {
    let code = &query.code;
    println!("{}", code);
    // 获取 token

    let auth_res = match exchange_code_for_token(code).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to fetch token: {}", e);
            return HttpResponse::InternalServerError().body("Failed to fetch token");
        }
    };

    let user_agent = _req.headers().get("User-Agent");
    let os = match user_agent {
        Some(agent) => {
            let agent_str = agent.to_str().unwrap_or("");
            if agent_str.contains("Windows") {
                "Windows"
            } else if agent_str.contains("Macintosh") {
                "macOS"
            } else {
                "Unknown"
            }
        }
        None => "Unknown",
    };
    println!("Detected OS: {}", os);

    // 从请求中恢复 originalUrl (这里假设从query 参数传递)
    // 在实际应用中，应该从 Cookie 或者 Session 中获取
    let original_url = match os {
        "Windows" => "http://infiniteclipboard.local/callback",
        "macOS" => "infiniteclipboard://localhost/callback",
        _ => "",
    };
    println!("original_url: {}", original_url);

    // 构建带有 token 的重定向 url
    let redirect_url = Url::parse(original_url)
        .unwrap()
        .join(&format!(
            "?token={}&email={}",
            auth_res.jwt_token, auth_res.email
        ))
        .unwrap();

    HttpResponse::Found()
        .append_header(("Location", redirect_url.to_string()))
        .finish()
}
