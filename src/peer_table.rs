use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub type PeerID = [u8; 32];

pub fn id_from_pubkey(_pubkey: &Public) -> PeerID {
    unimplemented!()
}

pub struct PeerTable(HashMap<PeerID, SocketAddr>);

pub type PeerTableHandle = Arc<Mutex<PeerTable>>;

impl PeerTable {
    pub fn add_peer(&mut self, id: PeerID, addr: SocketAddr) -> Option<SocketAddr> {
        self.0.insert(id, addr)
    }

    pub fn has_peer(&self, id: &PeerID) -> bool {
        self.0.contains_key(id)
    }

    pub fn peer_addr(&self, id: &PeerID) -> Option<&SocketAddr> {
        self.0.get(id)
    }
}
