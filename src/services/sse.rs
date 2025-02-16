use std::{io, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    get, http, middleware::Logger, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::extract::Path;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time;

use crate::broadcast::Broadcaster;

use super::auth::Claims;

#[derive(Deserialize)]
struct RoomQuery {
    room_id: String,
    client_id: String,
}

#[derive(Serialize,Deserialize,Debug)]
struct MessageContent {
}

#[derive(Deserialize)]
struct BroadcastMessage {
    message: Value,
}

#[get("/events/connect")]
async fn connect_to_room(
    query: web::Query<RoomQuery>,
    // user:Claims,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    // println!("user: {:?}", user.sub);
    println!("new client_id: {:?}", query.client_id);
    println!("room_id: {:?}", query.room_id);
    broadcaster
        .new_client(query.room_id.clone(), query.client_id.clone())
        .await
}

#[post("/events/broadcast/{room_id}/{client_id}")]
async fn broadcast_to_room(
    path: web::Path<(String, String)>,
    message: web::Json<BroadcastMessage>,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    // println!("user: {:?}", user.sub);
    let (room_id, client_id) = path.into_inner();
    broadcaster
        .broadcast_to_room(
            &room_id,
            &client_id,
            json!({"action":"receive_text","message":&message.message})
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

#[get("/events/connection/update/{room_id}/{client_id}")]
async fn update_connection(
    path: web::Path<(String, String)>,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    let (room_id, client_id) = path.into_inner();
    let mut room_map = broadcaster.inner.lock();
    println!("room size: {:?}", room_map.rooms.len());
    let result: Vec<_> = room_map.rooms.iter().map(|room|room.0).collect();
    println!("room:{:?}",result);

    let room = room_map.rooms.entry(room_id.clone()).or_default();

    let clients: Vec<_> = room
        .keys()
        .map(|client_id| json!({"clientID": client_id}))
        .collect();
    // drop(room);
    println!("client size:{:?}",room.len());

    let _= room;
    drop(room_map);
    
    println!("clients: {:?}", clients);
    let data =  json!({"action":"update_connection","message":{"devices":clients}});
    println!("data: {:?}",data);
    let data_str = data.to_string();
    // println!("data: {:?}", data_str.as_str());
    broadcaster
        .broadcast_to_room(
            room_id.clone().as_str(),
            client_id.clone().as_str(),
            data_str.as_str(),
            // "123",
            // json!({"action":"update_connection","message":json!({"devices":clients}).to_string()})
            //     .as_str()
            //     .unwrap(),
            false,
        )
        .await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "sent",
        "room": room_id,
        "from": client_id
    }))
}

#[get("/connect")]
async fn connect(
    query: web::Query<RoomQuery>,
    user: Claims,
    broadcaster: web::Data<Broadcaster>,
) -> impl Responder {
    // HttpResponse::Ok().body("connected")

    let count = broadcaster.inner.lock().rooms.capacity();

    // Thread::spawn(move ||async  {

    // });
    let stream = broadcaster
        .new_client(query.room_id.clone(), query.client_id.clone())
        .await;

    // let mut room_map = broadcaster.inner.lock();

    // let room = room_map.rooms.entry(query.room_id.clone()).or_default();
    // let clients: Vec<_> = room
    //     .keys()
    //     .map(|client_id| json!({"clientID": client_id}))
    //     .collect();
    // broadcaster.broadcast_to_room(
    //     query.room_id.clone().as_str(),
    //     query.client_id.clone().as_str(),
    //     json!({"action":"update_connection","message":json!({"devices":clients}).to_string()})
    //         .as_str()
    //         .unwrap(),
    // ).await;
    // tokio::spawn(async move {

    //     time::sleep(time::Duration::from_secs(2)).await;
    //     println!("s1");
    //     broadcaster.broadcast_to_room(
    //         query.room_id.clone().as_str(),
    //         query.client_id.clone().as_str(),
    //         json!({"action":"update_devices","message":{"count":count+1}}).as_str().unwrap()    ,
    //     ).await;
    //     println!("s2");
    // });

    return stream;
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
