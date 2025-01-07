
use std::{io, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    get, http, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::extract::Path;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::broadcast::Broadcaster;


#[get("/events")]
async fn event_stream(broadcaster: web::Data<Broadcaster>) -> impl Responder {
    broadcaster.new_client().await
}

#[get("/")]
async fn index() -> impl Responder {
    web::Html::new(include_str!("../index.html").to_owned())
}

#[post("/broadcast/{msg}")]
async fn broadcast_msg(
    broadcaster: web::Data<Broadcaster>,
    Path((msg,)): Path<(String,)>,
) -> impl Responder {
    broadcaster.broadcast(&msg).await;
    HttpResponse::Ok().body("msg sent")
}

