use crate::conn_manager::peer_table;
use aes_gcm::aead::{self, generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::{mpsc, oneshot};

pub fn new_encrypted_connection_task(
    read_half: OwnedReadHalf,
    pubkey: Public,
    cipher: Aes256Gcm,
    reads: mpsc::Sender<(Public, Vec<u8>)>,
) -> oneshot::Sender<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let read_fut = read_into_sender(pubkey, cipher.clone(), read_half, reads);
    tokio::spawn(async {
        tokio::select! {
            _ = read_fut => (),
            _ = cancel_rx => (),
        }
    });

    cancel_tx
}

async fn read_into_sender<R: AsyncReadExt + Unpin>(
    pubkey: Public,
    cipher: Aes256Gcm,
    mut reader: R,
    mut sender: mpsc::Sender<(Public, Vec<u8>)>,
) -> Result<(), ()> {
    // TODO(ross): What should the size of this buffer be?
    let mut len_buf = [0u8; 4];
    let mut buf = [0u8; 1024];
    while let Ok(n) = reader.read_exact(&mut len_buf).await {
        if n == 0 {
            // Reading 0 bytes usually indicates EOF.
            return Ok(());
        }
        let l = u32::from_be_bytes(len_buf);
        let enc_buf = &mut buf[..l as usize];
        reader.read_exact(enc_buf).await.map_err(|_| todo!())?;
        let dec = decrypt_aes_gcm(&cipher, enc_buf).expect("TODO");
        sender.send((pubkey, dec)).await.map_err(|_| ())?;
    }
    // TODO(ross): Should we try to keep reading from the connection after an error? Does it ever
    // make sense to do this?
    Err(())
}

pub struct EncryptedWriter {
    writer: OwnedWriteHalf,
    cipher: Aes256Gcm,
}

impl EncryptedWriter {
    pub async fn write_all(&mut self, msg: &[u8]) -> Result<(), Error> {
        let enc = encrypt_aes_gcm(&self.cipher, msg).map_err(Error::Encryption)?;
        let l: u32 = enc.len() as u32;
        let l_prefix = l.to_be_bytes();
        let mut len_prefixed = Vec::with_capacity(l_prefix.len() + l as usize);
        len_prefixed.extend_from_slice(&l_prefix);
        len_prefixed.extend_from_slice(&enc);
        self.writer
            .write_all(&len_prefixed)
            .await
            .map_err(Error::Write)
    }
}

fn encrypt_aes_gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that
    // this is safe, and also look into whether it will be better to generate the nonce locally
    // in a deterministic way so that both peers can determine the correct nonce locally.
    let nonce = rand::random::<[u8; 12]>();
    let nonce = GenericArray::from_slice(&nonce);
    let enc = cipher.encrypt(nonce, msg)?;
    let mut ret = Vec::with_capacity(nonce.len() + enc.len());
    ret.extend_from_slice(&nonce);
    ret.extend_from_slice(&enc);
    Ok(ret)
}

fn decrypt_aes_gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that
    // this is safe, and also look into whether it will be better to generate the nonce locally
    // in a deterministic way so that both peers can determine the correct nonce locally.
    let nonce = &msg[..12];
    let enc = &msg[12..];
    let nonce = GenericArray::from_slice(&nonce);
    cipher.decrypt(nonce, enc)
}

pub struct Connection {
    write_half: Option<EncryptedWriter>,
    cancel: oneshot::Sender<()>,
    key: [u8; 32],
}

#[derive(Debug)]
pub enum Error {
    Read(io::Error),
    Write(io::Error),
    Encryption(aead::Error),
    Decryption(aead::Error),
    ConnectionInUse,
}

impl Connection {
    pub fn new(key: [u8; 32], write_half: OwnedWriteHalf, cancel: oneshot::Sender<()>) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        let writer = EncryptedWriter {
            writer: write_half,
            cipher,
        };
        Self {
            write_half: Some(writer),
            cancel,
            key,
        }
    }

    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.write_half
            .as_mut()
            .ok_or(Error::ConnectionInUse)?
            .write_all(msg)
            .await
    }

    pub fn is_in_use(&self) -> bool {
        self.write_half.is_none()
    }

    pub fn take_writer(&mut self) -> Option<EncryptedWriter> {
        self.write_half.take()
    }

    pub fn give_back_writer(&mut self, writer: EncryptedWriter) {
        // TODO(ross): Should we return an error/panic if there was already a writer in the
        // connection? This case would probably represent violating an invariant.
        self.write_half = Some(writer);
    }
}

pub async fn keep_alive(
    stream: &mut TcpStream,
    cipher: &Aes256Gcm,
    own_pubkey: &Public,
    peer_pubkey: &Public,
    own_decision: bool,
) -> Result<bool, Error> {
    let own_id = peer_table::id_from_pubkey(own_pubkey);
    let peer_id = peer_table::id_from_pubkey(peer_pubkey);
    if own_id > peer_id {
        let msg = encrypt_aes_gcm(cipher, &[1]).map_err(Error::Encryption)?;
        stream.write_all(&msg).await.map_err(Error::Write)?;
        Ok(own_decision)
    } else {
        let mut buf = [0u8; 16 + 12 + 1]; // TODO(ross): Pick this size in a better way.
        stream.read_exact(&mut buf[..]).await.map_err(Error::Read)?;
        let dec = decrypt_aes_gcm(cipher, &buf).map_err(Error::Decryption)?;
        assert_eq!(dec.len(), 1);
        Ok(dec[0] == 1)
    }
}

pub struct ConnectionPool {
    max_connections: usize,
    connections: HashMap<SocketAddr, Connection>,
    reads_ref: mpsc::Sender<(Public, Vec<u8>)>,
}

#[derive(Debug)]
pub enum PoolError {
    TooManyConnections,
    PeerAddr(std::io::Error),
    ConnectionInUse,
}

impl ConnectionPool {
    pub fn new_with_max_connections_allocated(
        max_connections: usize,
    ) -> (Self, mpsc::Receiver<(Public, Vec<u8>)>) {
        let connections = HashMap::with_capacity(max_connections);
        let (tx, rx) = mpsc::channel(100);
        (
            Self {
                max_connections,
                connections,
                reads_ref: tx,
            },
            rx,
        )
    }

    pub fn add_connection(
        &mut self,
        stream: TcpStream,
        pubkey: Public,
        key: [u8; 32],
    ) -> Result<Option<Connection>, PoolError> {
        use PoolError::*;

        if self.connections.len() >= self.max_connections {
            return Err(TooManyConnections);
        }
        let peer_addr = stream.peer_addr().map_err(PeerAddr)?;
        if let Some(existing) = self.connections.get_mut(&peer_addr) {
            if existing.is_in_use() {
                return Err(ConnectionInUse);
            }
        }
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        let (read_half, write_half) = stream.into_split();
        let cancel =
            new_encrypted_connection_task(read_half, pubkey, cipher, self.reads_ref.clone());
        let conn = Connection::new(key, write_half, cancel);
        Ok(self.connections.insert(peer_addr, conn))
    }

    pub fn remove_connection(&mut self, addr: &SocketAddr) {
        if let Some(conn) = self.connections.remove(addr) {
            // We don't care if the receiver has been dropped, as this will mean that the task has
            // been cancelled anyway.
            conn.cancel.send(()).ok();
        }
    }

    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn is_full(&self) -> bool {
        self.num_connections() >= self.max_connections
    }

    pub fn get_conn_mut(&mut self, addr: &SocketAddr) -> Option<&mut Connection> {
        self.connections.get_mut(addr)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut Connection)> {
        self.connections.iter_mut()
    }
}
