use aes_gcm::aead::{self, generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Connection {
    stream: TcpStream,
    cipher: Aes256Gcm,
}

pub enum Error {
    Write(io::Error),
    Encryption(aead::Error),
    Decryption(aead::Error),
}

impl Connection {
    pub fn new(stream: TcpStream, key: &[u8]) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(key));
        Self { stream, cipher }
    }

    pub async fn write_encrypted_authenticated(&mut self, msg: &[u8]) -> Result<(), Error> {
        use Error::*;

        let nonce = rand::random::<[u8; 12]>();
        let nonce = GenericArray::from_slice(&nonce);
        let enc = self.cipher.encrypt(nonce, msg).map_err(Encryption)?;
        self.stream.write_all(&enc).await.map_err(Write)
    }
}

pub struct ConnectionPool {
    max_connections: usize,
    connections: HashMap<SocketAddr, Connection>,
}

pub enum PoolError {
    TooManyConnections,
    PeerAddr(std::io::Error),
}

impl ConnectionPool {
    pub fn add_connection(&mut self, conn: Connection) -> Result<Option<Connection>, PoolError> {
        use PoolError::*;

        if self.connections.len() >= self.max_connections {
            Err(TooManyConnections)
        } else {
            let peer_addr = conn.stream.peer_addr().map_err(PeerAddr)?;
            Ok(self.connections.insert(peer_addr, conn))
        }
    }

    pub fn get_conn_mut(&mut self, addr: &SocketAddr) -> Option<&mut Connection> {
        self.connections.get_mut(addr)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut Connection)> {
        self.connections.iter_mut()
    }
}
