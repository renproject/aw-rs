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

pub struct PeerTable(HashMap<Public, SocketAddr>);

impl PeerTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn connection_exists_for_peer(&self, pubkey: &Public) -> bool {
        self.0.contains_key(pubkey)
    }

    pub fn num_peers(&self) -> usize {
        self.0.len()
    }

    pub fn peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.0.iter()
    }

    pub fn add_peer(&mut self, pubkey: Public, addr: SocketAddr) -> Option<SocketAddr> {
        self.0.insert(pubkey, addr)
    }

    pub fn has_peer(&self, pubkey: &Public) -> bool {
        self.0.contains_key(pubkey)
    }

    pub fn peer_addr(&self, pubkey: &Public) -> Option<&SocketAddr> {
        self.0.get(pubkey)
    }
}
