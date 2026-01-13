use std::collections::hash_map::{Entry, HashMap};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};
use std::collections::HashSet;
use std::collections::BTreeSet;

use colored::Colorize;
use futures::Stream;
use rocket::data::ToByteUnit;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::stream::{stream, Event, EventStream};
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tokio::sync::{Notify, RwLock};

use rocket::tokio::sync::mpsc;


#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(short, long, default_value = "8000")]
    port: i32
}


impl Cli {
    pub fn from_port(port: i32) -> Self {
        Self { port }
    }
}

#[rocket::get("/rooms/<room_id>/subscribe")]
async fn subscribe(
    db: &State<Db>,
    mut shutdown: rocket::Shutdown,
    last_seen_msg: LastEventId,
    room_id: &str,
) -> EventStream<impl Stream<Item = Event>> {
    let room = db.get_room_or_create_empty(room_id).await;
    
    // clone room and room_id for disconnection notification
    let room_id_clone=room_id.to_owned();
    let room_clone = room.to_owned();

    let mut subscription = room.subscribe(last_seen_msg.0);
    EventStream::from(stream! {
        // 创建一个通道，用于接收 SSE 连接断开的信号
        let (_disconnect_tx, mut disconnect_rx) = mpsc::channel::<()>(1);
    
        // 启动一个异步任务来监听连接断开的信号
        tokio::spawn(async move {
            // 等待 SSE 连接断开的信号
            let _ = disconnect_rx.recv().await;
            
            // 连接断开后的提示
            println!("{}","Connection close.".bold());
            println!("   >> Room_id: {}",room_id_clone.bold());
            println!("   >> Remaining num: {}",room_clone.subscribers.load(Ordering::SeqCst).to_string().bold());
        });


        loop {
            let (id, msg) = tokio::select! {
                message = subscription.next() => message,
                _ = &mut shutdown => return
            };


            yield Event::data(msg)
                .event("new-message")
                .id(id.to_string());

        }
    }).heartbeat(std::time::Duration::from_secs(8))
}

#[rocket::post("/rooms/<room_id>/issue_unique_idx")]
async fn issue_idx(db: &State<Db>, room_id: &str) -> Json<IssuedUniqueIdx> {
    let room = db.get_room_or_create_empty(room_id).await;
    let idx = room.issue_unique_idx();

    println!(
        "{}{}",
        "Remote node join, the index of subscriber is ".green().bold(),
        room.subscribers.load(Ordering::SeqCst).to_string().bold()
    );

    Json::from(IssuedUniqueIdx { unique_idx: idx })
}

#[derive(Serialize, Deserialize, Debug)]
struct FixedIdxReq {
    idx: u16,
}

/// v2: issue a deterministic room index for a given stable party id.
///
/// - `party_id` is the user-chosen/stable id of the node (e.g. 1,3,...)
/// - `parties` is the set of participants for THIS computation session.
///
/// The manager canonicalizes `parties` (sort+dedup) and assigns
/// `room_idx = position(party_id in parties) + 1`.
#[derive(Serialize, Deserialize, Debug)]
struct PartyIdxReq {
    party_id: u16,
    parties: Vec<u16>,
}

#[rocket::post("/rooms/<room_id>/issue_idx_with_parties", format = "json", data = "<body>")]
async fn issue_idx_with_parties(
    db: &State<Db>,
    room_id: &str,
    body: Json<PartyIdxReq>,
) -> std::result::Result<Json<IssuedUniqueIdx>, Status> {
    let room = db.get_room_or_create_empty(room_id).await;
    let idx = room
        .issue_idx_with_parties(body.party_id, body.parties.clone())
        .await?;

    println!(
        "{}{}{}{}",
        "Remote node joined v2, party_id=".green().bold(),
        body.party_id.to_string().bold(),
        ", room_idx=".green().bold(),
        idx.to_string().bold(),
    );

    Ok(Json::from(IssuedUniqueIdx { unique_idx: idx }))
}

#[rocket::post("/rooms/<room_id>/issue_fixed_idx", format = "json", data = "<body>")]
async fn issue_fixed_idx(
    db: &State<Db>,
    room_id: &str,
    body: Json<FixedIdxReq>,
) -> std::result::Result<Json<IssuedUniqueIdx>, Status> {
    let room = db.get_room_or_create_empty(room_id).await;
    let idx = room.try_reserve_fixed_idx(body.idx).await?;

    println!(
        "{}{}",
        "Remote node reserved fixed idx ".green().bold(),
        idx.to_string().bold()
    );

    Ok(Json::from(IssuedUniqueIdx { unique_idx: idx }))
}

#[rocket::post("/rooms/<room_id>/broadcast", data = "<message>")]
async fn broadcast(db: &State<Db>, room_id: &str, message: String) -> Status {
    println!("{}", message);
    let room = db.get_room_or_create_empty(room_id).await;
    room.publish(message).await;
    Status::Ok
}

struct Db {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

struct Room {
    messages: RwLock<Vec<String>>,
    message_appeared: Notify,
    subscribers: AtomicU16,
    next_idx: AtomicU16,
    // ----------------------
    // Id model (v2)
    // ----------------------
    // We separate:
    // - party_id: user chosen/stable id (e.g. 1,3)
    // - room_idx: protocol/runtime index inside THIS room (always 1..k)
    //
    // room_idx is derived deterministically from the (canonicalized) party set
    // so it won't "drift" based on join order.
    party_set: RwLock<Option<Vec<u16>>>,
    party_to_room_idx: RwLock<HashMap<u16, u16>>,

    // Legacy: fixed index reservation (kept for compatibility)
    used_idx: RwLock<HashSet<u16>>,
}

impl Db {
    pub fn empty() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_room_or_create_empty(&self, room_id: &str) -> Arc<Room> {
        let rooms = self.rooms.read().await;
        if let Some(room) = rooms.get(room_id) {
            // If no one is watching this room - we need to clean it up first
            if !room.is_abandoned() {
                return room.clone();
            }
        }
        drop(rooms);

        let mut rooms = self.rooms.write().await;
        match rooms.entry(room_id.to_owned()) {
            Entry::Occupied(entry) if !entry.get().is_abandoned() => entry.get().clone(),
            Entry::Occupied(entry) => {
                let room = Arc::new(Room::empty());
                *entry.into_mut() = room.clone();
                room
            }
            Entry::Vacant(entry) => entry.insert(Arc::new(Room::empty())).clone(),
        }
    }
}

impl Room {
    pub fn empty() -> Self {
        Self {
            messages: RwLock::new(vec![]),
            message_appeared: Notify::new(),
            subscribers: AtomicU16::new(0),
            next_idx: AtomicU16::new(1),
            party_set: RwLock::new(None),
            party_to_room_idx: RwLock::new(HashMap::new()),
            used_idx: RwLock::new(HashSet::new()),
        }
    }

    pub async fn publish(self: &Arc<Self>, message: String) {
        let mut messages = self.messages.write().await;
        messages.push(message);
        self.message_appeared.notify_waiters();
    }

    pub fn subscribe(self: Arc<Self>, last_seen_msg: Option<u16>) -> Subscription {
        self.subscribers.fetch_add(1, Ordering::SeqCst);
        Subscription {
            room: self,
            next_event: last_seen_msg.map(|i| i + 1).unwrap_or(0),
        }
    }

    pub fn is_abandoned(&self) -> bool {
        self.subscribers.load(Ordering::SeqCst) == 0
    }

    pub fn issue_unique_idx(&self) -> u16 {
        self.next_idx.fetch_add(1, Ordering::SeqCst)
    }

    /// v2: deterministically assign a contiguous room index (1..k) based on the
    /// canonicalized party set for this room.
    ///
    /// This prevents "id drift" even when parties join in different orders,
    /// and enables signing with subsets like {1,3} by mapping them to room_idx {1,2}
    /// in sorted party-id order.
    pub async fn issue_idx_with_parties(
        &self,
        party_id: u16,
        parties: Vec<u16>,
    ) -> std::result::Result<u16, Status> {
        if party_id == 0 {
            return Err(Status::BadRequest);
        }

        // canonicalize: sort + dedup + validate
        let mut set = BTreeSet::<u16>::new();
        for p in parties {
            if p == 0 {
                return Err(Status::BadRequest);
            }
            set.insert(p);
        }
        if set.is_empty() {
            return Err(Status::BadRequest);
        }
        let canonical: Vec<u16> = set.iter().copied().collect();
        if !set.contains(&party_id) {
            return Err(Status::BadRequest);
        }

        // Initialize room party set on first request; otherwise ensure it matches
        // (same computation session must use the same participant list).
        {
            let mut room_party_set = self.party_set.write().await;
            match &*room_party_set {
                None => {
                    *room_party_set = Some(canonical.clone());
                }
                Some(existing) => {
                    if existing != &canonical {
                        // Different caller is trying to use the same room_id with a different party set
                        return Err(Status::Conflict);
                    }
                }
            }
        }

        // Deterministic room index: 1-based position inside canonical list.
        let room_idx = canonical
            .iter()
            .position(|p| *p == party_id)
            .ok_or(Status::BadRequest)? as u16
            + 1;

        // Stable mapping (for reconnects); do not allow two different party_ids to claim the same room_idx.
        let mut map = self.party_to_room_idx.write().await;
        if let Some(existing) = map.get(&party_id) {
            return Ok(*existing);
        }
        if map.values().any(|v| *v == room_idx) {
            return Err(Status::Conflict);
        }
        map.insert(party_id, room_idx);
        Ok(room_idx)
    }

    // pub fn leave(&self){
    //     self.subscribers.fetch_sub(1, Ordering::SeqCst);
    // }
    pub async fn try_reserve_fixed_idx(&self, idx: u16) -> std::result::Result<u16, Status> {
        if idx == 0 {
            return Err(Status::BadRequest);
        }
        let mut used = self.used_idx.write().await;
        if used.contains(&idx) {
            return Err(Status::Conflict);
        }
        used.insert(idx);
        Ok(idx)
    }
}

struct Subscription {
    room: Arc<Room>,
    next_event: u16,
}

impl Subscription {
    pub async fn next(&mut self) -> (u16, String) {
        loop {
            let history = self.room.messages.read().await;
            if let Some(msg) = history.get(usize::from(self.next_event)) {
                let event_id = self.next_event;
                self.next_event = event_id + 1;
                return (event_id, msg.clone());
            }
            let notification = self.room.message_appeared.notified();
            drop(history);
            notification.await;
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.room.subscribers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Represents a header Last-Event-ID
struct LastEventId(Option<u16>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LastEventId {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header = request
            .headers()
            .get_one("Last-Event-ID")
            .map(|id| id.parse::<u16>());
        match header {
            Some(Ok(last_seen_msg)) => Outcome::Success(LastEventId(Some(last_seen_msg))),
            Some(Err(_parse_err)) => {
                Outcome::Failure((Status::BadRequest, "last seen msg id is not valid"))
            }
            None => Outcome::Success(LastEventId(None)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct IssuedUniqueIdx {
    unique_idx: u16,
}

// // 需要rocket manage之后 中attach      // .attach(MyFairing)
// use rocket::fairing::{Fairing, Info, Kind};
// struct MyFairing;
// #[rocket::async_trait]
// impl Fairing for MyFairing {
//     fn info(&self) -> Info {
//         Info {
//             name: "My Custom Fairing",
//             kind: Kind::Request | Kind::Response |Kind::Shutdown
//         }
//     }
//     async fn on_request(&self, request: &mut Request<'_>, _: &mut rocket::Data<'_>) {
//         println!("new request======================: {:?}",request.client_ip());
//     }
//     async fn on_response<'r>(&self,_request: &'r rocket::Request<'_>, response: &mut rocket::Response<'r>){
//         println!("resopnse=============={:?}",response)
//     }

//     async fn on_shutdown(&self,_: &rocket::Rocket<rocket::Orbit>){
//         println!("shutdown===================");
//     }

// }

// // 需要rocket manage 之前中resigter   //.register("/", rocket::catchers![sse_stream_closed])
// #[rocket::catch(500)]
// fn sse_closed()  {

//     println!("{}","Remote leave, current subscribers is ".yellow())
// }

pub async fn gg20_sm_manager(args:Cli) -> Result<(), Box<dyn std::error::Error>> {
    let port=args.port;
    let figment = rocket::Config::figment()
        .merge((
            "limits",
            rocket::data::Limits::new().limit("string", 100.megabytes()),
        ))
        .merge(("port", port));

    rocket::custom(figment)
        .mount(
            "/",
            rocket::routes![
                subscribe,
                issue_idx,
                issue_idx_with_parties,
                issue_fixed_idx,
                broadcast
            ],
        )
        .manage(Db::empty())
        .launch()
        .await?;
    Ok(())
}
