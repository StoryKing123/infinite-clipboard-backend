use std::{sync::Arc, time::Duration, collections::HashMap};

use actix_web::{rt::time::interval, Error};
use actix_web_lab::{
    sse::{self, Sse},
    util::InfallibleStream,
};
use futures_util::future;
use parking_lot::Mutex;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct Broadcaster {
    pub inner: Mutex<BroadcasterInner>,
}

#[derive(Debug, Clone, Default)]
pub struct BroadcasterInner {
    // room_id -> (client_id -> sender)
    pub rooms: HashMap<String, HashMap<String, mpsc::Sender<sse::Event>>>,
}

impl Broadcaster {
    pub fn create() -> Arc<Self> {
        let this = Arc::new(Broadcaster {
            inner: Mutex::new(BroadcasterInner::default()),
        });

        Broadcaster::spawn_ping(Arc::clone(&this));

        this
    }

    fn spawn_ping(this: Arc<Self>) {
        actix_web::rt::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;
                this.remove_stale_clients().await;
            }
        });
    }

    async fn remove_stale_clients(&self) {
        let mut inner = self.inner.lock();
        let mut rooms_to_remove = Vec::new();

        // println!("before remove:{:?}",inner.rooms.len());
        // for room in inner.rooms.iter(){
        //     println!("{:?}",room);
        // }

        for (room_id, clients) in inner.rooms.iter_mut() {
            let mut active_clients = HashMap::new();

            for (client_id, client) in clients.iter() {
                if client
                    .send(sse::Event::Comment("ping".into()))
                    .await
                    .is_ok()
                {
                    active_clients.insert(client_id.clone(), client.clone());
                }
            }

            if active_clients.is_empty() {
                rooms_to_remove.push(room_id.clone());
            } else {
                *clients = active_clients;
            }
        }

        // Remove empty rooms
        for room_id in rooms_to_remove {
            inner.rooms.remove(&room_id);
        }
        // println!("after remove:{:?}",inner.rooms.len());
        // for room in inner.rooms.iter(){
        //     println!("{:?}",room);
        // }
    }

    pub async fn new_client(&self, room_id: String, client_id: String) -> Result< Sse<InfallibleStream<ReceiverStream<sse::Event>>> ,Error>{
        let (tx, rx) = mpsc::channel(100);

        let mut inner = self.inner.lock();
        let room = inner.rooms.entry(room_id.clone()).or_default();
        room.insert(client_id.clone(), tx.clone());
        // Send initial connection message
        let clients: Vec<_> = room.keys().map(|client_id| json!({"clientID": client_id})).collect();
        println!("clients: {:?}", clients);

        println!("new client");
        println!("rooms size:{:?}",inner.rooms.len());
        println!("client size:{:?}",clients.len());
        let _ = tx
            .send(sse::Data::new(json!({"devices":clients}).to_string())
                .event("connection")
                .into())
            .await;



        Ok(Sse::from_infallible_receiver(rx))
    }

    // async fn remove_client(&self, room_id: &str, client_id: &str) {
    //     let mut inner = self.inner.lock();
    //     if let Some(room) = inner.rooms.get_mut(room_id) {
    //         room.remove(client_id);
    //         if room.is_empty() {
    //             inner.rooms.remove(room_id);
    //         }
    //     }
    // }

    pub async fn broadcast_to_room(&self, room_id: &str, from_client_id: &str, msg: &str, exclude_self: bool) {
        let clients = {
            let inner = self.inner.lock();
            if let Some(room) = inner.rooms.get(room_id) {
                if exclude_self {
                    room.iter()
                        .filter(|(id, _)| *id != from_client_id)
                        .map(|(_, client)| client.clone())
                        .collect::<Vec<_>>()
                } else {
                    room.iter()
                    .map(|(_, client)| client.clone())
                    .collect::<Vec<_>>()
                }
            } else {
                return;
            }
        };

        println!("clients: {:?}", clients.len());
        let send_futures = clients
            .iter()
            .map(|client| {
                println!("sending message to client: {:?}", client);
                let msg = sse::Data::new(msg).event("message").into();
                client.send(msg)
            });

        let _ = future::join_all(send_futures).await;
    }
}
