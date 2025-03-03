mod services;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, RwLock},
};

use actix_cors::Cors;
use actix_web::{
    get, http,
    middleware::Logger,
    post,
    web::{self, service},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::extract::Path;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

mod broadcast;
use self::broadcast::Broadcaster;
#[derive(Clone)]
struct AppState {
    codes: Arc<RwLock<HashMap<String, (String, u64)>>>,
}

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let data = Broadcaster::create();

    // let app_state = Arc::new(web::Data::new(AppState {
    //     codes: Arc::new(RwLock::new(HashMap::new())),
    // }));

    let app_state = Arc::new(  AppState {
        codes: Arc::new(RwLock::new(HashMap::new())),
    });

    // let app_state = Arc::new( RwLock::new(HashMap::<String, u64>::new()));
    // let state = web::Data::new()
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(Arc::clone(&data)))
            // .app_data(Arc::clone(&app_state))
            .app_data(web::Data::from(Arc::clone(&app_state)))
            .wrap(
                Cors::default()
                    .allowed_origin_fn(|origin, _req_head| {
                        // origin.as_bytes().ends_with(b".rust-lang.org")
                        true
                    })
                    .allow_any_header()
                    .allow_any_method()
                    // .allowed_methods(vec!["GET", "POST"])
                    // .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                    // .allowed_header(http::header::CONTENT_TYPE)
                    .max_age(3600),
            )
            .service(greet)
            .service(services::auth::github_callback)
            .service(services::sse::connect_to_room)
            .service(services::sse::broadcast_to_room)
            .service(services::sse::index)
            .service(services::sse::update_connection)
            .service(services::auth::login_handler)
            .service(services::auth::send_code_handler)
            .service(services::auth::auth0_callback)
        // .service(connect)
    })
    .bind(("0.0.0.0", 3000))?
    .workers(2)
    .run()
    .await
}
