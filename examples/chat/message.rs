use parity_crypto::publickey::Public;
use std::convert::TryFrom;
use std::str::{self, Utf8Error};

#[derive(Default)]
pub struct Message {
    pub from: Public,
    pub message: String,
}

impl Message {
    pub fn new(from: Public, message: String) -> Self {
        Self { from, message }
    }

    pub fn new_from_pubkey_and_bytes(from: Public, msg_bytes: &[u8]) -> Result<Self, Utf8Error> {
        let mut ret = Self {
            from,
            message: String::with_capacity(msg_bytes.len()),
        };
        ret.message.push_str(str::from_utf8(msg_bytes)?);
        Ok(ret)
    }
}

impl From<Message> for Vec<u8> {
    fn from(msg: Message) -> Self {
        let mut bytes = Vec::with_capacity(msg.message.len() + 64);
        bytes.extend_from_slice(msg.from.as_bytes());
        bytes.extend_from_slice(msg.message.as_bytes());
        bytes
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Utf8Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut msg = Self {
            from: Public::default(),
            message: String::with_capacity(bytes.len() - 64),
        };
        let (from_bytes, message) = bytes.split_at(64);
        msg.from.assign_from_slice(from_bytes);
        msg.message.push_str(str::from_utf8(message)?);
        Ok(msg)
    }
}
