use std::{io, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    get, http, middleware::Logger, post, web, App, Either, HttpRequest, HttpResponse, HttpServer,
    Responder,
};
use actix_web_lab::{extract::Path, sse::Sse, util::InfallibleStream};
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time;
use tokio_stream::wrappers::ReceiverStream;

use crate::broadcast::Broadcaster;

use super::auth::Claims;

#[derive(Deserialize)]
struct RoomQuery {
    client_id: String,
    header_Authorization: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct MessageContent {}

#[derive(Deserialize)]
struct BroadcastMessage {
    message: Value,
}

#[get("/events/connect")]
async fn connect_to_room(
    query: web::Query<RoomQuery>,
    // user:Claims,
    broadcaster: web::Data<Broadcaster>,
    // ) -> impl Responder {
) -> Either<Sse<InfallibleStream<ReceiverStream<actix_web_lab::sse::Event>>>, impl Responder> {
    let token = query.header_Authorization.trim_start_matches("Bearer ");
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoded = jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret("secret".as_ref()),
        &validation,
    );

    match decoded {
        Ok(token_data) => {
            println!("Decoded claims: {:?}", token_data.claims);
            let room_id = token_data.claims.sub;
            println!("new client_id: {:?}", query.client_id);
            println!("room_id: {:?}", room_id);
            // return Ok("123213");
            match broadcaster
                .new_client(room_id.clone(), query.client_id.clone())
                .await
            {
                // Ok(stream)=>stream,
                Ok(stream) => Either::Left(stream),
                Err(_) => {
                    Either::Right(HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to create client connection"
                    })))
                }
            }
        }
        Err(err) => {
            return Either::Right(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid token",
                "message": "Authentication failed"
            })));
            // println!("JWT decode error: {:?}", err);
        }
    }
}

#[post("/events/broadcast/{client_id}")]
async fn broadcast_to_room(
    path: web::Path<( String)>,
    user:Claims,
    message: web::Json<BroadcastMessage>,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    // println!("user: {:?}", user.sub);
    let room_id = user.sub.clone();
    let ( client_id) = path.into_inner();
    broadcaster
        .broadcast_to_room(
            &room_id,
            &client_id,
            json!({"action":"receive_message","message":&message.message})
                .to_string()
                .as_str(),
            true,
        )
        .await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "sent",
        "room": room_id,
        "from": client_id
    }))
}

#[get("/events/connection/update/{client_id}")]
async fn update_connection(
    path: web::Path<( String)>,
    broadcaster: web::Data<Broadcaster>,
    user: Claims
) -> impl Responder {
    let room_id = user.sub.clone();
    let ( client_id) = path.into_inner();
    let mut room_map = broadcaster.inner.lock();
    println!("room size: {:?}", room_map.rooms.len());
    let result: Vec<_> = room_map.rooms.iter().map(|room| room.0).collect();
    println!("room:{:?}", result);

    let room = room_map.rooms.entry(room_id.clone()).or_default();

    let clients: Vec<_> = room
        .keys()
        .map(|client_id| json!({"clientID": client_id}))
        .collect();
    // drop(room);
    println!("client size:{:?}", room.len());

    let _ = room;
    drop(room_map);

    println!("clients: {:?}", clients);
    let data = json!({"action":"update_connection","message":{"devices":clients}});
    println!("data: {:?}", data);
    let data_str = data.to_string();
    broadcaster
        .broadcast_to_room(
            room_id.clone().as_str(),
            client_id.clone().as_str(),
            data_str.as_str(),
            false,
        )
        .await;
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
