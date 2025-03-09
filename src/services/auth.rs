use std::{future::Future, pin::Pin, time::{SystemTime, UNIX_EPOCH}};

use actix_web::{error::{Error, ErrorUnauthorized}, get, post, web::{self, Payload}, FromRequest, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
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
            let secret = "secret".to_string();
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






#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}


#[get("/validate")]
async fn validate_token(
    // auth: BearerAuth,
    query: web::Query<TokenQuery>
    // data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    // let token = &query.token;
    let token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiaXNzIjoiaHR0cHM6Ly9kZXYtZ2M4MHVvMGxrdzM4cDZmbS51cy5hdXRoMC5jb20vIn0..7OKokBCxPVBtf6Ae.QT6C03xqTdP3PacU-gRTQT12S4Mc66r2I-3fdkAagNXX4yi0ptvC4uFs-5ezyCwVN_NFTvSjlOgiO9TH9m0YF41DDfzXsNxxjsOPtpmSuyyO3LQ2FpTE2u_VE6wxaNIZoktF5vd5lW5zN7sqXFlzUDjHusWBXvn3yBMZLLUsNqg4vTa2lVSl1CWuncIJJ1Z4daPHVhKKNT2D3kRXn3X8xC5v49qltFUANx42wSwofTXQT1oKhXctdYgJleIHc94P0FB42At5xINf4b6xRInAo55cKTOypS1q8DUVCJd1Dq3oF1ssoWrRIEhogn7OXROCbBV8YOFhkFv-faU_gYMyJ4HX.8LncFw0drskkyTKB1WTCkA";
    // 获取 Auth0 的公钥 (通常从 JWKS 端点动态获取，这里简化为硬编码密钥)
    let auth0_domain = "dev-gc80uo0lkw38p6fm.us.auth0.com";
    let jwks_url = format!("https://{}/.well-known/jwks.json", auth0_domain);
    // 在实际生产中，应使用 reqwest 获取 JWKS 并解析公钥
    let secret = "-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJZveKVs905Ct6MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1nYzgwdW8wbGt3MzhwNmZtLnVzLmF1dGgwLmNvbTAeFw0yNTAzMDIx
NTI2MDNaFw0zODExMDkxNTI2MDNaMCwxKjAoBgNVBAMTIWRldi1nYzgwdW8wbGt3
MzhwNmZtLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALPbYO821nml/oJHMfEziMfl33XfL4a4fcBqIjCPVtkWJDIseYraI+/UXBXR
Anwchop4+BMgz+KLhzclx6E4udSrFoZwFA6DkdqrcPIWojthSzWAvkVeLpMFNnwn
9Gkyaz/4YGz2la1aucx+Evt+C1QRlOcV1ofqV6ShekWO7k3M1mrswDLjK5vz7P7r
r/BcVaQUT67LouVM5kl1jvZbN8konObpWhMoNgGh7fLLcQC2Eys482t49HKOTDNp
eCSNh/gw5lgNeGfX2BOGE7n4s0XoHRlDuRwUPZDK2dogFdf6EHhyZ8SF1rk8clNa
a/B2gAv54O10JaTgzMZI1hx3vl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUdeDauNpDJ6C2a1gAeQyTnw7RCpwwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQCfXEsVJcEmBstf/PCYXX1/I6fowrs+FYliSrND6N5X
Kj9h2jCTJcANgIgLpd1IkSLPyTFtSBLUMDqq+oMeDdJNn1184dNBLj2yk3BtFHCA
+ykA92+Da0BUY3VRiQsVaboPcUP4Y0VaOIBzxRS7duKynI02CQcUyuVGFyo3zr16
IhhpijWLxKYeQNAhKs009CTK38bc690JpK/l6bXXJLMq0y8+VJ25rMCv6+/nRkCc
EvkpPfuKZCbKvRaTvMqyNuGGUXTrkj0+II6KL4x+8QfCm78hU4ZPANQhpwVzwW4m
RJ5FQteSg/GvYRhFnMKPNF+1v6saIaN5bNi3AznaLP3U
-----END CERTIFICATE-----".as_bytes(); // 替换为实际的密钥或从 JWKS 获取
    // 配置校验参数
    let mut validation = Validation::new(Algorithm::HS256); // 根据 Auth0 配置选择算法
    // validation.set_audience(&["https://dev-gc80uo0lkw38p6fm.us.auth0.com/api/v2/"]);
    validation.set_issuer(&[format!("https://{}/", auth0_domain)]);
    // 解码并校验 token
    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation,
    ) {
        Ok(token_data) => {
            // token 有效，返回成功响应
            Ok(HttpResponse::Ok().json(format!(
                "Token validated! User: {}",
                token_data.claims.sub
            )))
        }
        Err(err) => {
            // token 无效，返回错误
            Ok(HttpResponse::Unauthorized().body(format!("Invalid token: {}", err)))
        }
    }
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
                        println!("{:?}",token_response);
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
                                            // response.email = Some(email.to_string());

                                            // 使用email生成JWT
                                            let claims = Claims {
                                                sub: email.to_string(),
                                                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
                                            };
                                            
                                            let token = encode(
                                                &Header::default(),
                                                &claims,
                                                &EncodingKey::from_secret("secret".as_ref()),
                                            ).unwrap();
                                            
                                            let login_response = LoginResponse{email:email.clone().into(),token:token};

                                            // response.id_token = token;
                                            HttpResponse::Ok().json(login_response)
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
#[derive(Serialize, Deserialize,Debug)]
struct Auth0TokenResponse {
    access_token: String,
    id_token: String,  // Auth0特有的id_token
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
}
#[derive(Serialize, Deserialize,Debug)]
struct LoginResponse{
    email:String,
    token:String
}


// Auth0错误响应结构体
#[derive(Serialize, Deserialize)]
struct Auth0ErrorResponse {
    error: String,
    error_description: Option<String>,
}


