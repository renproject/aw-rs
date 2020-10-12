use parity_crypto::publickey::Public;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;

pub type PeerID = [u8; 32];

pub fn id_from_pubkey(pubkey: &Public) -> PeerID {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.finalize().into()
}

pub struct PeerTable(HashMap<PeerID, SocketAddr>);

impl PeerTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn connection_exists_for_peer(&self, id: &PeerID) -> bool {
        self.0.contains_key(id)
    }

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
