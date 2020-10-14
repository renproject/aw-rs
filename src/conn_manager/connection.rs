use aes_gcm::aead::{self, generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

pub fn new_encrypted_connection_task(
    stream: TcpStream,
    pubkey: Public,
    cipher: Aes256Gcm,
    reads: mpsc::Sender<(Public, Vec<u8>)>,
    writes: mpsc::Receiver<(Vec<u8>, oneshot::Sender<tokio::io::Result<()>>)>,
) -> oneshot::Sender<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (reader, writer) = stream.into_split();
    let read_fut = read_into_sender(pubkey, cipher.clone(), reader, reads);
    let write_fut = write_out_from_receiver(cipher, writes, writer);
    tokio::spawn(async {
        tokio::select! {
            _ = futures::future::join(read_fut, write_fut) => (),
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

async fn write_out_from_receiver<W: AsyncWriteExt + Unpin>(
    cipher: Aes256Gcm,
    mut receiver: mpsc::Receiver<(Vec<u8>, oneshot::Sender<tokio::io::Result<()>>)>,
    mut writer: W,
) -> Result<(), ()> {
    while let Some((data, res)) = receiver.recv().await {
        // FIXME(ross): Nonce reuse is catastrophic, so make sure to decide on how to pick the
        // nonce before using this in any important systems. We will set the nonce to a constant
        // for now for testing purposes.
        let nonce = [0u8; 12];
        let nonce = GenericArray::from_slice(&nonce);
        let enc = cipher.encrypt(nonce, &data[..]).expect("TODO");

        res.send(writer.write_all(&enc).await).ok();
    }
    Err(())
}

pub struct Connection {
    writer: mpsc::Sender<(Vec<u8>, oneshot::Sender<tokio::io::Result<()>>)>,
    cancel: oneshot::Sender<()>,
    key: [u8; 32],
}

#[derive(Debug)]
pub enum Error {
    Read(io::Error),
    Write(io::Error),
    Encryption(aead::Error),
    Decryption(aead::Error),
}

impl Connection {
    pub fn new(
        key: [u8; 32],
        writer: mpsc::Sender<(Vec<u8>, oneshot::Sender<tokio::io::Result<()>>)>,
        cancel: oneshot::Sender<()>,
    ) -> Self {
        Self {
            writer,
            cancel,
            key,
        }
    }

    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        use Error::*;

        let (res_tx, res_rx) = oneshot::channel();
        self.writer
            .send((msg.into(), res_tx))
            .await
            .map_err(|e| Write(tokio::io::Error::new(tokio::io::ErrorKind::BrokenPipe, e)))?;
        res_rx
            .await
            .unwrap_or_else(|e| Err(tokio::io::Error::new(tokio::io::ErrorKind::BrokenPipe, e)))
            .map_err(Write)
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
                    let (write_tx, write_rx) = mpsc::channel(100);
                    let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
                    let cancel = new_encrypted_connection_task(
                        stream,
                        pubkey,
                        cipher,
                        self.reads_ref.clone(),
                        write_rx,
                    );
                    let conn = Connection::new(key, write_tx, cancel);
                    return Ok(Some(std::mem::replace(existing, conn)));
                }
            }
            let (write_tx, write_rx) = mpsc::channel(100);
            let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
            let cancel = new_encrypted_connection_task(
                stream,
                pubkey,
                cipher,
                self.reads_ref.clone(),
                write_rx,
            );
            let conn = Connection::new(key, write_tx, cancel);
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
        self.num_connections() == self.max_connections
    }

    pub fn get_conn_mut(&mut self, addr: &SocketAddr) -> Option<&mut Connection> {
        self.connections.get_mut(addr)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut Connection)> {
        self.connections.iter_mut()
    }
}
