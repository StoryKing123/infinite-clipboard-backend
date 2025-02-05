mod services;
use std::{io, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    get, http, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::extract::Path;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

mod broadcast;
use self::broadcast::Broadcaster;


#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}



#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
let data = Broadcaster::create();

    HttpServer::new(move || {

        App::new()
            .app_data(web::Data::from(Arc::clone(&data)))
            .wrap(
                Cors::default()
                    .allowed_origin("https://www.rust-lang.org")
                    .allowed_origin_fn(|origin, _req_head| {
                        // origin.as_bytes().ends_with(b".rust-lang.org")
                        true
                    })
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                    .allowed_header(http::header::CONTENT_TYPE)
                    .max_age(3600),
            )
            .service(greet)
            .service(services::auth::github_callback)
            .service(services::sse::connect_to_room)
            .service(services::sse::broadcast_to_room)
            .service(services::sse::index)
            .service(services::sse::update_connection)
        // .service(connect)
    })
    .bind(("127.0.0.1", 3000))?
    .workers(2) 
    .run()
    .await
}
