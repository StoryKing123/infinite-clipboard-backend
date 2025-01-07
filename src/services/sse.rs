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

#[derive(Deserialize)]
struct RoomQuery {
    room_id: String,
    client_id: String,
}

#[derive(Deserialize)]
struct BroadcastMessage {
    message: String,
}

#[get("/events/connect")]
async fn connect_to_room(
    query: web::Query<RoomQuery>,
    broadcaster: web::Data<Broadcaster>
) -> impl Responder {
    broadcaster.new_client(query.room_id.clone(), query.client_id.clone()).await
}

#[post("/events/broadcast/{room_id}/{client_id}")]
async fn broadcast_to_room(
    path: web::Path<(String, String)>,
    message: web::Json<BroadcastMessage>,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    let (room_id, client_id) = path.into_inner();
    broadcaster.broadcast_to_room(&room_id, &client_id, &message.message).await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "sent",
        "room": room_id,
        "from": client_id
    }))
}

#[get("/")]
async fn index() -> impl Responder {
    web::Html::new(include_str!("../index.html").to_owned())
}

// #[post("/broadcast/{msg}")]
// async fn broadcast_msg(
//     broadcaster: web::Data<Broadcaster>,
//     Path((msg,)): Path<(String,)>,
// ) -> impl Responder {
//     broadcaster.broadcast(&msg).await;
//     HttpResponse::Ok().body("msg sent")
// }

