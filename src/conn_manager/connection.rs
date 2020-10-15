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
    let mut buf = [0u8; 1024];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            // Reading 0 bytes usually indicates EOF.
            return Ok(());
        }

        // FIXME(ross): Nonce reuse is catastrophic, so make sure to decide on how to pick the
        // nonce before using this in any important systems. We will set the nonce to a constant
        // for now for testing purposes.
        let nonce = [0u8; 12];
        let nonce = GenericArray::from_slice(&nonce);
        let dec = cipher.decrypt(nonce, &buf[..n]).expect("TODO");

        sender.send((pubkey, dec)).await.map_err(|_| ())?;
    }
    // TODO(ross): Should we try to keep reading from the connection after an error? Does it ever
    // make sense to do this?
    Err(())
}

pub struct Connection {
    write_half: OwnedWriteHalf,
    cancel: oneshot::Sender<()>,
    key: [u8; 32],
    cipher: Aes256Gcm,
}

#[derive(Debug)]
pub enum Error {
    Read(io::Error),
    Write(io::Error),
    Encryption(aead::Error),
    Decryption(aead::Error),
}

impl Connection {
    pub fn new(key: [u8; 32], write_half: OwnedWriteHalf, cancel: oneshot::Sender<()>) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        Self {
            write_half,
            cancel,
            key,
            cipher,
        }
    }

    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        // FIXME(ross): Nonce reuse is catastrophic, so make sure to decide on how to pick the
        // nonce before using this in any important systems. We will set the nonce to a constant
        // for now for testing purposes.
        let nonce = [0u8; 12];
        let nonce = GenericArray::from_slice(&nonce);
        let enc = self.cipher.encrypt(nonce, msg).map_err(Error::Encryption)?;

        self.write_half.write_all(&enc).await.map_err(Error::Write)
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
            Err(TooManyConnections)
        } else {
            let peer_addr = stream.peer_addr().map_err(PeerAddr)?;
            if let Some(existing) = self.connections.get_mut(&peer_addr) {
                if existing.key > key {
                    let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
                    let (read_half, write_half) = stream.into_split();
                    let cancel = new_encrypted_connection_task(
                        read_half,
                        pubkey,
                        cipher,
                        self.reads_ref.clone(),
                    );
                    let conn = Connection::new(key, write_half, cancel);
                    return Ok(Some(std::mem::replace(existing, conn)));
                }
            }
            let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
            let (read_half, write_half) = stream.into_split();
            let cancel =
                new_encrypted_connection_task(read_half, pubkey, cipher, self.reads_ref.clone());
            let conn = Connection::new(key, write_half, cancel);
            Ok(self.connections.insert(peer_addr, conn))
        }
    }

    pub fn remove_connection(&mut self, addr: &SocketAddr) {
        if let Some(conn) = self.connections.remove(addr) {
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
