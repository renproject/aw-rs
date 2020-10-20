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
    write_half: OwnedWriteHalf,
    receiver: mpsc::Receiver<(Vec<u8>, oneshot::Sender<Result<(), Error>>)>,
    sender: mpsc::Sender<(Public, Result<Vec<u8>, Error>)>,
    pubkey: Public,
    cipher: Aes256Gcm,
) -> oneshot::Sender<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let read_fut = read_into_sender(pubkey, cipher.clone(), read_half, sender);
    let write_fut = write_from_receiver(cipher.clone(), write_half, receiver);
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
    mut sender: mpsc::Sender<(Public, Result<Vec<u8>, Error>)>,
) -> Result<(), ()> {
    let mut len_buf = [0u8; 4];
    // TODO(ross): What should the size of this buffer be?
    // NOTE(ross): If a change to using a vector is used, make sure that there are checks on how
    // much memory is allocated based on the length prefix sent by the peer.
    let mut buf = [0u8; 1024];
    while let Ok(n) = reader.read_exact(&mut len_buf).await {
        if n == 0 {
            // Reading 0 bytes usually indicates EOF.
            return Ok(());
        }
        let l = u32::from_be_bytes(len_buf);
        let enc_buf = &mut buf[..l as usize];
        let res = reader.read_exact(enc_buf).await.map_err(Error::Read);
        if let Some(e) = res.err() {
            if sender.send((pubkey, Err(e))).await.is_err() {
                // There is no one consuming the incoming messages, so we stop reading them.
                return Ok(());
            }
        } else {
            let dec = decrypt_aes_gcm(&cipher, enc_buf).map_err(Error::Decryption);
            if sender.send((pubkey, dec)).await.is_err() {
                // There is no one consuming the incoming messages, so we stop reading them.
                return Ok(());
            }
        }
    }
    // TODO(ross): Should we try to keep reading from the connection after an error? Does it ever
    // make sense to do this?
    Err(())
}

async fn write_from_receiver(
    cipher: Aes256Gcm,
    mut write_half: OwnedWriteHalf,
    mut receiver: mpsc::Receiver<(Vec<u8>, oneshot::Sender<Result<(), Error>>)>,
) {
    while let Some((msg, responder)) = receiver.recv().await {
        match encrypt_aes_gcm(&cipher, &msg).map_err(Error::Encryption) {
            Ok(enc) => {
                let length_prefixed = length_encode(&enc);
                let res = write_half
                    .write_all(&length_prefixed)
                    .await
                    .map_err(Error::Write);
                responder.send(res).ok();
            }
            Err(e) => {
                responder.send(Err(e)).ok();
            }
        }
    }
}

fn length_encode(msg: &[u8]) -> Vec<u8> {
    let l: u32 = msg.len() as u32;
    let l_prefix = l.to_be_bytes();
    let mut len_prefixed = Vec::with_capacity(l_prefix.len() + l as usize);
    len_prefixed.extend_from_slice(&l_prefix);
    len_prefixed.extend_from_slice(&msg);
    len_prefixed
}

fn encrypt_aes_gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that this
    // is safe, and also look into whether it will be better to generate the nonce in a
    // deterministic way so that both peers can determine the correct nonce locally.
    let nonce = rand::random::<[u8; 12]>();
    let nonce = GenericArray::from_slice(&nonce);
    let enc = cipher.encrypt(nonce, msg)?;
    let mut ret = Vec::with_capacity(nonce.len() + enc.len());
    ret.extend_from_slice(&nonce);
    ret.extend_from_slice(&enc);
    Ok(ret)
}

fn decrypt_aes_gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that this
    // is safe, and also look into whether it will be better to generate the nonce in a
    // deterministic way so that both peers can determine the correct nonce locally.
    let nonce = &msg[..12];
    let enc = &msg[12..];
    let nonce = GenericArray::from_slice(&nonce);
    cipher.decrypt(nonce, enc)
}

pub struct Connection {
    writer: ConnectionWriter,
    cancel: oneshot::Sender<()>,
}

#[derive(Debug)]
pub enum Error {
    Read(io::Error),
    Write(io::Error),
    Receive,
    Send,
    Encryption(aead::Error),
    Decryption(aead::Error),
}

impl Connection {
    pub fn new(
        key: [u8; 32],
        pubkey: Public,
        stream: TcpStream,
        incoming_sender: mpsc::Sender<(Public, Result<Vec<u8>, Error>)>,
    ) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        let (read_half, write_half) = stream.into_split();
        // TODO(ross): Figure out what to do with channel buffer sizes.
        let (outgoing_sender, outgoing_receiver) = mpsc::channel(100);
        let cancel = new_encrypted_connection_task(
            read_half,
            write_half,
            outgoing_receiver,
            incoming_sender,
            pubkey,
            cipher,
        );
        Self {
            writer: ConnectionWriter::new(outgoing_sender),
            cancel,
        }
    }

    pub fn cancel(self) {
        self.cancel.send(()).ok();
    }

    pub fn writer(&self) -> ConnectionWriter {
        self.writer.clone()
    }

    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.writer.write(msg).await
    }
}

#[derive(Clone)]
pub struct ConnectionWriter {
    writer: mpsc::Sender<(Vec<u8>, oneshot::Sender<Result<(), Error>>)>,
}

impl ConnectionWriter {
    fn new(writer: mpsc::Sender<(Vec<u8>, oneshot::Sender<Result<(), Error>>)>) -> Self {
        Self { writer }
    }

    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        let (responder, response) = oneshot::channel();
        self.writer
            .send((msg.to_vec(), responder))
            .await
            .map_err(|_| Error::Send)?;
        response.await.map_err(|_| Error::Receive)?
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
        stream
            .write_all(&length_encode(&msg))
            .await
            .map_err(Error::Write)?;
        Ok(own_decision)
    } else {
        let mut buf = [0u8; 16 + 12 + 1]; // TODO(ross): Pick this size in a better way.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf[..])
            .await
            .map_err(Error::Read)?;
        let l = u32::from_be_bytes(len_buf);
        let enc_buf = &mut buf[..l as usize];
        stream.read_exact(enc_buf).await.map_err(Error::Read)?;
        let dec = decrypt_aes_gcm(cipher, enc_buf).map_err(Error::Decryption)?;
        assert_eq!(dec.len(), 1);
        Ok(dec[0] == 1)
    }
}

pub struct ConnectionPool {
    max_connections: usize,
    connections: HashMap<SocketAddr, Connection>,
    reads_ref: mpsc::Sender<(Public, Result<Vec<u8>, Error>)>,
}

#[derive(Debug)]
pub enum PoolError {
    TooManyConnections,
    PeerAddr(std::io::Error),
}

impl ConnectionPool {
    pub fn new_with_max_connections_allocated(
        max_connections: usize,
    ) -> (Self, mpsc::Receiver<(Public, Result<Vec<u8>, Error>)>) {
        let connections = HashMap::with_capacity(max_connections);
        // TODO(ross): Decide how to pick this buffer length.
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
        let conn = Connection::new(key, pubkey, stream, self.reads_ref.clone());
        Ok(self.connections.insert(peer_addr, conn))
    }

    // FIXME(ross): Currently this could be called while another task is writing to the connection,
    // which may not necessarily cause a panic or anything but would probably be unexpected
    // behvaviour.
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

    pub fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &Connection)> {
        self.connections.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut Connection)> {
        self.connections.iter_mut()
    }
}
