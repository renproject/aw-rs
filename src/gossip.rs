use crate::conn_manager::connection::SynDecider;
use crate::message::{self, Message, Variant};
use crate::util;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub enum Incoming {
    Header(Message),
    Message(Message, Vec<u8>),
}

pub fn handle_incoming<F, T: SynDecider>(
    incoming: Incoming,
    will_pull: F,
    received: Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
    requested: Arc<Mutex<HashMap<Vec<u8>, ()>>>,
) -> Option<Incoming>
where
    F: Fn(&Message) -> bool,
{
    match incoming {
        Incoming::Header(header) => match header.variant {
            Variant::Push => {
                let mut received = util::get_lock(&received);
                received.insert(header.data.clone(), None);
                if will_pull(&header) {
                    Some(Incoming::Header(Message::new(
                        message::V1,
                        Variant::Pull,
                        message::UNUSED_PEER_ID,
                        header.data,
                    )))
                } else {
                    None
                }
            }
            Variant::Pull => {
                let received = util::get_lock(&received);
                if let Some(Some(msg)) = received.get(header.data.as_slice()) {
                    Some(Incoming::Message(
                        Message::new(
                            message::V1,
                            Variant::Syn,
                            message::UNUSED_PEER_ID,
                            header.data,
                        ),
                        msg.clone(),
                    ))
                } else {
                    None
                }
            }
            Variant::Syn => {
                // TODO(ross): Syn headers should only be processed along side the associated data,
                // and hence only be present in the Incoming::Message variant. What should we do
                // here?
                todo!()
            }
        },
        Incoming::Message(header, msg) => {
            let mut requested = util::get_lock(&requested);
            let mut received = util::get_lock(&received);
            if requested.remove(header.data.as_slice()).is_some() {
                // TODO(ross): The message was not actually requested but we are receiving it
                // anyway. What should we do in a case like this?
            }
            received
                .get_mut(header.data.as_slice())
                .and_then(|value| value.replace(msg));
            None
        }
    }
}

#[derive(Clone)]
pub struct Decider {
    requested: Arc<Mutex<HashMap<Vec<u8>, ()>>>,
}

impl SynDecider for Decider {
    fn accept_syn(&mut self, msg: &Message) -> bool {
        let requested = util::get_lock(&self.requested);
        requested.contains_key(msg.data.as_slice())
    }
}

impl Decider {
    pub fn new() -> Self {
        Self {
            requested: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
