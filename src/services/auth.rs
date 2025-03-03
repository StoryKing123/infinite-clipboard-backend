use std::{future::Future, pin::Pin, time::{SystemTime, UNIX_EPOCH}};

use actix_web::{error::{Error, ErrorUnauthorized}, get, post, web::{self, Payload}, FromRequest, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{encode,decode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;

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



async fn send_verification_code(email: &str, code: &str) {
    println!("Send code {} to {}", code, email);
}
// 请求参数结构
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    code: String,
}


#[derive(Deserialize)]
struct SendCodeRequest {
    email: String,
}


// 生成6位数字验证码
fn generate_code() -> String {
    rand::rng()
        .random_range(100000..999999)
        .to_string()
}

// 获取当前时间戳（秒）
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}


// 处理登录请求
#[post("/login")]
pub async fn login_handler(
    req: web::Json<LoginRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let email = req.email.clone();
    let code = req.code.clone();

    // 从内存中获取验证码
    let stored = data.codes.read().unwrap().get(&email).cloned();
    
    match stored {
        Some((stored_code, timestamp)) => {
            // 检查验证码有效期（5分钟）
            if current_timestamp() - timestamp > 300 {
                data.codes.write().unwrap().remove(&email);
                return HttpResponse::Unauthorized().body("Verification code expired");
            }

            if stored_code == code {
                // 登录成功，清除验证码
                data.codes.write().unwrap().remove(&email);


                let my_claims = Claims {
                    sub: email.clone(),
                    exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
                };
            
                let key = EncodingKey::from_secret("your-secret-key".as_ref()); // Replace with your secret key
            
                let token = encode(&Header::default(), &my_claims, &key).unwrap();

                HttpResponse::Ok().body(format!( "Login successful,{}",token))
            } else {
                HttpResponse::Unauthorized().body("Invalid verification code")
            }
        }
        None => HttpResponse::NotFound().body("No verification code found for this email"),
    }
}
// 处理发送验证码请求
#[post("/send_code")]
pub async  fn send_code_handler(body: web::Json<SendCodeRequest>, data: web::Data<AppState>) -> impl Responder {
    let email = body.email.clone();
    
    // 简单验证邮箱格式
    if !email.contains('@') {
        return HttpResponse::BadRequest().body("Invalid email format");
    }

    let code = generate_code();
    let timestamp = current_timestamp();
    
    // 存储验证码
    data.codes
        .write()
        .unwrap()
        .insert(email.clone(), (code.clone(), timestamp));

    // 模拟发送邮件
    send_verification_code(&email, &code).await;

    HttpResponse::Ok().body("Verification code sent")
}

// 处理Auth0 OAuth2.0回调，通过code获取token
#[post("/auth/callback")]
pub async fn auth0_callback(
    body: web::Json<Auth0CodeRequest>
    // client: web::Data<Client>,
) -> impl Responder {
    let code = &body.code;

    // Auth0特定的请求参数
    let params = [
        ("client_id", "iYJHTznuBHb33JBGxjTbNKG8pMiJCqaj"),
        ("client_secret", "MNTULJcTadfwAgLtBX6I1n4311VdS0eSkOoGGxVPeEVActQtNlqTff8dyKXBR7o0"),
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", "http://localhost:1420")
        // ("audience", "your_auth0_api_identifier"),  // Auth0特有的audience参数
    ];

    // 发送请求到Auth0的token endpoint
    let client = reqwest::Client::new();
    let request = client
        .post("https://dev-gc80uo0lkw38p6fm.us.auth0.com/oauth/token")
        .form(&params);

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Auth0TokenResponse>().await {
                    Ok(token_response) => {
                        // 使用access_token获取用户信息
                        let client = reqwest::Client::new();
                        let user_info = client
                            .get("https://dev-gc80uo0lkw38p6fm.us.auth0.com/userinfo")
                            .bearer_auth(&token_response.access_token)
                            .send()
                            .await;

                        match user_info {
                            Ok(user_response) => {
                                if user_response.status().is_success() {
                                    match user_response.json::<serde_json::Value>().await {
                                        Ok(user_data) => {
                                            // 获取email并添加到响应中
                                            let email = user_data["email"].as_str().unwrap_or("");
                                            let mut response = token_response;
                                            response.email = Some(email.to_string());
                                            HttpResponse::Ok().json(response)
                                        }
                                        Err(_) => HttpResponse::InternalServerError().body("Failed to parse user info")
                                    }
                                } else {
                                    HttpResponse::Unauthorized().body("Failed to get user info")
                                }
                            }
                            Err(_) => HttpResponse::InternalServerError().body("Failed to connect to Auth0 userinfo endpoint")
                        }
                    }
                    Err(_) => HttpResponse::InternalServerError().body("Failed to parse token response"),
                }
            } else {
                // 从Auth0获取详细的错误信息
                let error_msg = match response.json::<Auth0ErrorResponse>().await {
                    Ok(err) => err.error_description.unwrap_or("Unknown error".to_string()),
                    Err(_) => "Failed to parse error response".to_string(),
                };
                HttpResponse::Unauthorized().body(error_msg)
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to connect to Auth0 server"),
    }
}

// Auth0 code请求结构体
#[derive(Deserialize)]
struct Auth0CodeRequest {
    code: String,
}

// Auth0 token响应结构体
#[derive(Serialize, Deserialize)]
struct Auth0TokenResponse {
    access_token: String,
    id_token: String,  // Auth0特有的id_token
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    email: Option<String>,
    scope: String,
}

// Auth0错误响应结构体
#[derive(Serialize, Deserialize)]
struct Auth0ErrorResponse {
    error: String,
    error_description: Option<String>,
}


