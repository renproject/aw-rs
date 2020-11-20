use ethereum_types::H256;
use parity_crypto::publickey::{self, Public, Secret, Signature};
use rand::seq::{IteratorRandom, SliceRandom};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{AddrParseError, SocketAddr};
use std::str::{self, FromStr, Utf8Error};

pub type PeerID = [u8; 32];

pub fn id_from_pubkey(pubkey: &Public) -> PeerID {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone)]
pub struct SignedAddress {
    pub address: SocketAddr,
    pub signature: Signature,
}

impl SignedAddress {
    pub fn new(address: SocketAddr, secret: &Secret) -> Result<Self, publickey::Error> {
        let mut hasher = Sha256::new();
        hasher.update(address.to_string().as_bytes());
        let message = H256::from_slice(hasher.finalize().as_slice());
        let signature = publickey::sign(secret, &message)?;
        Ok(Self { address, signature })
    }

    pub fn signatory(&self) -> Result<Public, publickey::Error> {
        let mut hasher = Sha256::new();
        hasher.update(self.address.to_string().as_bytes());
        let msg = hasher.finalize();
        publickey::recover(&self.signature, &H256::from_slice(msg.as_slice()))
    }

    pub fn from_bytes_with_tail(
        bytes: &[u8],
    ) -> Result<(Self, &[u8]), SignedAddressTryFromBytesError> {
        // Address length prefix.
        if bytes.len() < 4 {
            return Err(SignedAddressTryFromBytesError::LenPrefixLen(bytes.len()));
        }
        let (len_bytes, rest) = bytes.split_at(4);
        let mut len_bytes_arr = [0; 4];
        len_bytes_arr.copy_from_slice(len_bytes);
        let addr_bytes_len = u32::from_be_bytes(len_bytes_arr);

        // Address.
        if rest.len() < addr_bytes_len as usize {
            return Err(SignedAddressTryFromBytesError::AddrLen(
                addr_bytes_len as usize,
                rest.len(),
            ));
        }
        let (addr_bytes, rest) = rest.split_at(addr_bytes_len as usize);
        let addr_str = str::from_utf8(addr_bytes)?;
        let address = SocketAddr::from_str(addr_str)?;

        // Signature.
        if rest.len() < 65 {
            return Err(SignedAddressTryFromBytesError::SigLen(rest.len()));
        }
        let (sig_bytes, rest) = rest.split_at(65);
        let mut sig_bytes_arr = [0; 65];
        sig_bytes_arr.copy_from_slice(sig_bytes);
        let signature = Signature::from(sig_bytes_arr);

        Ok((SignedAddress { address, signature }, rest))
    }
}

impl From<SignedAddress> for Vec<u8> {
    fn from(addr: SignedAddress) -> Self {
        let addr_string = addr.address.to_string();
        let addr_bytes = addr_string.as_bytes();
        let addr_bytes_len = addr_bytes.len() as u32;
        let sig_bytes: [u8; 65] = addr.signature.into();
        let mut vec = Vec::with_capacity(65 + 4 + addr_bytes_len as usize);
        vec.extend_from_slice(&addr_bytes_len.to_be_bytes());
        vec.extend_from_slice(addr_bytes);
        vec.extend_from_slice(&sig_bytes);
        vec
    }
}

impl From<SignedAddress> for SocketAddr {
    fn from(signed_addr: SignedAddress) -> Self {
        signed_addr.address
    }
}

#[derive(Debug)]
pub enum SignedAddressTryFromBytesError {
    Utf8(Utf8Error),
    AddrParse(AddrParseError),
    LenPrefixLen(usize),
    AddrLen(usize, usize),
    SigLen(usize),
}

impl From<Utf8Error> for SignedAddressTryFromBytesError {
    fn from(e: Utf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<AddrParseError> for SignedAddressTryFromBytesError {
    fn from(e: AddrParseError) -> Self {
        Self::AddrParse(e)
    }
}

impl TryFrom<Vec<u8>> for SignedAddress {
    type Error = SignedAddressTryFromBytesError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Address length prefix.
        if bytes.len() < 4 {
            return Err(SignedAddressTryFromBytesError::LenPrefixLen(bytes.len()));
        }
        let (len_bytes, rest) = bytes.split_at(4);
        let mut len_bytes_arr = [0; 4];
        len_bytes_arr.copy_from_slice(len_bytes);
        let addr_bytes_len = u32::from_be_bytes(len_bytes_arr);

        // Address.
        if rest.len() < addr_bytes_len as usize {
            return Err(SignedAddressTryFromBytesError::AddrLen(
                addr_bytes_len as usize,
                rest.len(),
            ));
        }
        let (addr_bytes, sig_bytes) = rest.split_at(addr_bytes_len as usize);
        let addr_str = str::from_utf8(addr_bytes)?;
        let address = SocketAddr::from_str(addr_str)?;

        // Signature.
        if sig_bytes.len() != 65 {
            return Err(SignedAddressTryFromBytesError::SigLen(sig_bytes.len()));
        }
        let mut sig_bytes_arr = [0; 65];
        sig_bytes_arr.copy_from_slice(sig_bytes);
        let signature = Signature::from(sig_bytes_arr);

        Ok(SignedAddress { address, signature })
    }
}

pub struct PeerTable {
    unsigned_map: HashMap<Public, SocketAddr>,
    signed_map: HashMap<Public, SignedAddress>,
    vec: Vec<Public>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            unsigned_map: HashMap::new(),
            signed_map: HashMap::new(),
            vec: Vec::new(),
        }
    }

    pub fn connection_exists_for_peer(&self, pubkey: &Public) -> bool {
        self.unsigned_map.contains_key(pubkey) || self.signed_map.contains_key(pubkey)
    }

    pub fn num_peers(&self) -> usize {
        self.vec.len()
    }

    pub fn unsigned_peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.unsigned_map.iter()
    }

    pub fn signed_peers(&self) -> impl Iterator<Item = (&Public, &SignedAddress)> {
        self.signed_map.iter()
    }

    pub fn peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.unsigned_map.iter().chain(
            self.signed_map
                .iter()
                .map(|(pubkey, addr)| (pubkey, &addr.address)),
        )
    }

    pub fn add_unsigned_peer(&mut self, pubkey: Public, addr: SocketAddr) -> Option<SocketAddr> {
        if !self.has_peer(&pubkey) {
            self.vec.push(pubkey);
        }
        self.unsigned_map.insert(pubkey, addr)
    }

    pub fn add_signed_peer(
        &mut self,
        pubkey: Public,
        addr: SignedAddress,
    ) -> Option<SignedAddress> {
        if !self.has_peer(&pubkey) {
            self.vec.push(pubkey);
        }
        self.signed_map.insert(pubkey, addr)
    }

    pub fn has_peer(&self, pubkey: &Public) -> bool {
        self.unsigned_map.contains_key(pubkey) || self.signed_map.contains_key(pubkey)
    }

    pub fn peer_socket_addr(&self, pubkey: &Public) -> Option<&SocketAddr> {
        self.unsigned_map
            .get(pubkey)
            .or(self.signed_map.get(pubkey).map(|addr| &addr.address))
    }

    pub fn random_peer_subset(&self, n: usize) -> Vec<Public> {
        self.vec
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect()
    }

    pub fn random_signed_address_subset(&self, n: usize) -> Vec<SignedAddress> {
        self.signed_map
            .values()
            .cloned()
            .choose_multiple(&mut rand::thread_rng(), n)
    }
}
