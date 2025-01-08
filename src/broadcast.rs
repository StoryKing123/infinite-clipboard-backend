use std::{sync::Arc, time::Duration, collections::HashMap};

use actix_web::rt::time::interval;
use actix_web_lab::{
    sse::{self, Sse},
    util::InfallibleStream,
};
use futures_util::future;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub struct Broadcaster {
    inner: Mutex<BroadcasterInner>,
}

#[derive(Debug, Clone, Default)]
struct BroadcasterInner {
    // room_id -> (client_id -> sender)
    rooms: HashMap<String, HashMap<String, mpsc::Sender<sse::Event>>>,
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
    }

    pub async fn new_client(&self, room_id: String, client_id: String) -> Sse<InfallibleStream<ReceiverStream<sse::Event>>> {
        let (tx, rx) = mpsc::channel(10);

        let mut inner = self.inner.lock();
        let room = inner.rooms.entry(room_id.clone()).or_default();
        room.insert(client_id.clone(), tx.clone());

        // Send initial connection message
        let _ = tx
            .send(sse::Data::new(format!("Connected to room: {}", room_id))
                .event("connection")
                .into())
            .await;

        Sse::from_infallible_receiver(rx)
    }

    pub async fn broadcast_to_room(&self, room_id: &str, from_client_id: &str, msg: &str) {
        let clients = {
            let inner = self.inner.lock();
            println!("rooms: {:?}", inner.rooms.len());
            if let Some(room) = inner.rooms.get(room_id) {
                room.iter()
                    .filter(|(id, _)| *id != from_client_id)
                    .map(|(_, client)| client.clone())
                    .collect::<Vec<_>>()
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
