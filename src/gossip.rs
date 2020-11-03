use crate::conn_manager::peer_table;
use crate::conn_manager::{self, connection::SynDecider, ConnectionManager};
use crate::message::{self, Header, Message, Variant, V1};
use crate::util;
use futures::future::Future;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::stream::StreamExt;
use tokio::sync::mpsc;

pub fn gossip_task<F>(
    buffer_size: usize,
    alpha: usize,
    will_pull: F,
    decider: &Decider,
    conn_manager: Arc<Mutex<ConnectionManager<Decider>>>,
) -> (
    impl Future<Output = Result<(), mpsc::error::TrySendError<(Public, Vec<u8>)>>>,
    mpsc::Sender<(Public, Message)>,
    mpsc::Sender<(Public, Vec<u8>, Vec<u8>)>,
    mpsc::Receiver<(Public, Vec<u8>)>,
)
where
    F: Fn(&Header) -> bool,
{
    let (network_sender, network_receiver) = mpsc::channel(buffer_size);
    let (user_out_sender, user_out_receiver) = mpsc::channel(buffer_size);
    let (user_in_sender, user_in_receiver) = mpsc::channel(buffer_size);
    let received = Arc::new(Mutex::new(HashMap::new()));
    let requested = decider.requested.clone();
    let fut = consumer_fut(
        alpha,
        network_receiver,
        user_in_receiver,
        user_out_sender,
        will_pull,
        received,
        requested,
        conn_manager,
    );

    (fut, network_sender, user_in_sender, user_out_receiver)
}

async fn consumer_fut<F>(
    alpha: usize,
    network_receiver: mpsc::Receiver<(Public, Message)>,
    user_receiver: mpsc::Receiver<(Public, Vec<u8>, Vec<u8>)>,
    user_sender: mpsc::Sender<(Public, Vec<u8>)>,
    will_pull: F,
    received: Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
    requested: Arc<Mutex<HashMap<Vec<u8>, ()>>>,
    conn_manager: Arc<Mutex<ConnectionManager<Decider>>>,
) -> Result<(), mpsc::error::TrySendError<(Public, Vec<u8>)>>
where
    F: Fn(&Header) -> bool,
{
    let network_fut = network_fut(
        alpha,
        network_receiver,
        user_sender,
        will_pull,
        received.clone(),
        requested,
        conn_manager.clone(),
    );
    let user_fut = user_fut(user_receiver, received, conn_manager);

    futures::future::join(network_fut, user_fut).await.0
}

async fn user_fut(
    mut user_receiver: mpsc::Receiver<(Public, Vec<u8>, Vec<u8>)>,
    received: Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
    conn_manager: Arc<Mutex<ConnectionManager<Decider>>>,
) {
    while let Some((pubkey, key, message)) = user_receiver.recv().await {
        {
            let mut received = util::get_lock(&received);
            received.insert(key.clone(), Some(message));
        }
        let header = Header::new(V1, Variant::Push, peer_table::id_from_pubkey(&pubkey), key);
        let message = Message::Header(header);
        conn_manager::try_send_peer(&conn_manager, &pubkey, message)
            .await
            .expect("TODO");
    }
}

async fn network_fut<F>(
    alpha: usize,
    mut network_receiver: mpsc::Receiver<(Public, Message)>,
    mut user_sender: mpsc::Sender<(Public, Vec<u8>)>,
    will_pull: F,
    received: Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
    requested: Arc<Mutex<HashMap<Vec<u8>, ()>>>,
    conn_manager: Arc<Mutex<ConnectionManager<Decider>>>,
) -> Result<(), mpsc::error::TrySendError<(Public, Vec<u8>)>>
where
    F: Fn(&Header) -> bool,
{
    while let Some((pubkey, message)) = network_receiver.next().await {
        if let Message::Header(header) = &message {
            if header.variant == Variant::Push {
                let contains_key = {
                    let received = util::get_lock(&received);
                    received.contains_key(header.key.as_slice())
                };
                // We only forward a header to other peers if we have not already done so for the
                // given header.
                if !contains_key {
                    let peers = {
                        let conn_manager = util::get_lock(&conn_manager);
                        conn_manager.random_peer_subset(alpha)
                    };
                    // TODO(ross): Ideally we should keep trying to send to peers until we are
                    // reasonably confident that `alpha` of them will receive the message;
                    // currently it is possible that anywhere between 0 and `alpha` peers will
                    // receive the message given that we don't even check that we have a connection
                    // for the given peer.
                    futures::future::join_all(peers.iter().map(|peer| {
                        conn_manager::try_send_peer(&conn_manager, peer, message.clone())
                    }))
                    .await;
                }
            }
        }

        match handle_incoming(message, &will_pull, &received, &requested) {
            Some(Response::User(msg)) => user_sender.try_send((pubkey, msg))?,
            Some(Response::Network(msg)) => {
                conn_manager::try_send_peer(&conn_manager, &pubkey, msg)
                    .await
                    .err()
                    .map(|_e| {
                        // TODO(ross): Should we do seomthing about this error?
                    });
            }
            _ => (),
        }
    }
    Ok(())
}

enum Response {
    Network(Message),
    User(Vec<u8>),
}

fn handle_incoming<F>(
    incoming: Message,
    will_pull: &F,
    received: &Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
    requested: &Arc<Mutex<HashMap<Vec<u8>, ()>>>,
) -> Option<Response>
where
    F: Fn(&Header) -> bool,
{
    match incoming {
        Message::Header(header) => match header.variant {
            Variant::Push => {
                let mut received = util::get_lock(&received);
                if received.contains_key(header.key.as_slice()) {
                    // If the key is already in the map then either we are the originator of the
                    // message, or we have already received the `Push` header and possibly sent out
                    // a corresponding `Pull`. In either case, we do not want to pull again.
                    None
                } else {
                    received.insert(header.key.clone(), None);
                    if will_pull(&header) {
                        let mut requested = util::get_lock(&requested);
                        requested.insert(header.key.clone(), ());
                        Some(Response::Network(Message::Header(Header::new(
                            message::V1,
                            Variant::Pull,
                            message::UNUSED_PEER_ID,
                            header.key,
                        ))))
                    } else {
                        None
                    }
                }
            }
            Variant::Pull => {
                let received = util::get_lock(&received);
                if let Some(Some(msg)) = received.get(header.key.as_slice()) {
                    Some(Response::Network(Message::Syn(header.key, msg.clone())))
                } else {
                    None
                }
            }
            Variant::Syn => {
                // TODO(ross): Syn headers should only be processed along side the associated data,
                // and hence only be present in the Message::Header variant. What should we do
                // here?
                todo!()
            }
        },
        Message::Syn(key, msg) => {
            let mut requested = util::get_lock(&requested);
            let mut received = util::get_lock(&received);
            if requested.remove(key.as_slice()).is_some() {
                // TODO(ross): The message was not actually requested but we are receiving it
                // anyway. What should we do here?
            }
            received
                .get_mut(key.as_slice())
                .and_then(|value| value.replace(msg.clone()));
            Some(Response::User(msg))
        }
    }
}

#[derive(Clone)]
pub struct Decider {
    requested: Arc<Mutex<HashMap<Vec<u8>, ()>>>,
}

impl SynDecider for Decider {
    fn syn_requested(&mut self, msg: &Header) -> bool {
        let requested = util::get_lock(&self.requested);
        requested.contains_key(msg.key.as_slice())
    }
}

impl Decider {
    pub fn new() -> Self {
        Self {
            requested: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
