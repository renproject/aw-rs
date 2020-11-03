use parity_crypto::publickey::Public;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;

pub type PeerID = [u8; 32];

pub fn id_from_pubkey(pubkey: &Public) -> PeerID {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.finalize().into()
}

pub struct PeerTable {
    map: HashMap<Public, SocketAddr>,
    vec: Vec<Public>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            vec: Vec::new(),
        }
    }

    pub fn connection_exists_for_peer(&self, pubkey: &Public) -> bool {
        self.map.contains_key(pubkey)
    }

    pub fn num_peers(&self) -> usize {
        self.vec.len()
    }

    pub fn peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.map.iter()
    }

    pub fn add_peer(&mut self, pubkey: Public, addr: SocketAddr) -> Option<SocketAddr> {
        self.vec.push(pubkey);
        self.map.insert(pubkey, addr)
    }

    pub fn has_peer(&self, pubkey: &Public) -> bool {
        self.map.contains_key(pubkey)
    }

    pub fn peer_addr(&self, pubkey: &Public) -> Option<&SocketAddr> {
        self.map.get(pubkey)
    }

    pub fn random_peer_subset(&self, n: usize) -> Vec<Public> {
        self.vec
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect()
    }
}
