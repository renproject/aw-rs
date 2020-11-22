use crate::conn_manager::peer_table::PeerID;
use parity_crypto::publickey::Public;
use std::convert::{TryFrom, TryInto};

pub const GOSSIP_PEER_ID: [u8; 32] = [0xff; 32];
pub const UNUSED_PEER_ID: [u8; 32] = [0x00; 32];

pub type Version = u16;

pub const V1: Version = 1;

pub const VAR_PUSH: u16 = 1;
pub const VAR_PULL: u16 = 2;
pub const VAR_SYN: u16 = 3;
pub const VAR_PING: u16 = 4;
pub const VAR_PONG: u16 = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Variant {
    Push,
    Pull,
    Syn,
    Ping,
    Pong,
}

impl From<Variant> for u16 {
    fn from(var: Variant) -> Self {
        use Variant::*;
        match var {
            Push => VAR_PUSH,
            Pull => VAR_PULL,
            Syn => VAR_SYN,
            Ping => VAR_PING,
            Pong => VAR_PONG,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum U16TryFromVariantError {
    InvalidVariant,
}

impl From<U16TryFromVariantError> for Error {
    fn from(e: U16TryFromVariantError) -> Self {
        match e {
            U16TryFromVariantError::InvalidVariant => Error::InvalidVariant,
        }
    }
}

impl TryFrom<u16> for Variant {
    type Error = U16TryFromVariantError;

    fn try_from(n: u16) -> Result<Self, Self::Error> {
        use Variant::*;
        match n {
            VAR_PUSH => Ok(Push),
            VAR_PULL => Ok(Pull),
            VAR_SYN => Ok(Syn),
            VAR_PING => Ok(Ping),
            VAR_PONG => Ok(Pong),
            _ => Err(U16TryFromVariantError::InvalidVariant),
        }
    }
}

pub enum To {
    Peer(Public),
    Subnet([u8; 32]),
    Gossip,
}

#[derive(Debug, Clone)]
pub enum Message {
    Header(Header),
    Syn(Header, Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: Version,
    pub variant: Variant,
    pub to: PeerID,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    UnsupportedVersion,
    InvalidVariant,
    InvalidTo,
}

impl Header {
    pub fn new(version: Version, variant: Variant, to: PeerID, data: Vec<u8>) -> Self {
        Self {
            version,
            variant,
            to,
            data,
        }
    }

    pub fn from_bytes(mut vec: Vec<u8>) -> Result<Self, Error> {
        use Error::*;
        let data = vec.as_slice();
        if data.len() < 2 {
            return Err(InvalidVersion);
        }
        let (version_bytes, data) = data.split_at(2);
        let version: Version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);
        match version {
            V1 => {
                if data.len() < 2 {
                    return Err(InvalidVariant);
                }
                let (variant_bytes, data) = data.split_at(2);
                let variant = u16::from_be_bytes([variant_bytes[0], variant_bytes[1]]);
                let variant = variant.try_into()?;

                if data.len() < 32 {
                    return Err(InvalidTo);
                }
                let (to_bytes, _data) = data.split_at(32);
                let mut to = PeerID::default();
                to.copy_from_slice(to_bytes);
                Ok(Self {
                    version,
                    variant,
                    to,
                    data: vec.split_off(36),
                })
            }
            _ => Err(UnsupportedVersion),
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let Self {
            version,
            variant,
            to,
            data,
        } = self;
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&u16::from(variant).to_be_bytes());
        bytes.extend_from_slice(&to);
        bytes.extend_from_slice(data.as_slice());
        bytes
    }
}
