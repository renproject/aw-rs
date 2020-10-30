use crate::conn_manager::peer_table;
use crate::message::{self, Message, Variant};
use aes_gcm::aead::{self, generic_array::GenericArray, NewAead};
use aes_gcm::Aes256Gcm;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::{
    mpsc::{self, error::SendError},
    oneshot::{self, error::RecvError},
};

#[macro_use]
mod encode;

use encode::{NONCE_SIZE, TAG_SIZE};

pub fn new_encrypted_connection_task<T: SynDecider + Send + 'static>(
    read_half: OwnedReadHalf,
    write_half: OwnedWriteHalf,
    pubkey: Public,
    cipher: Aes256Gcm,
    max_header_len: usize,
    max_data_len: usize,
    buffer_size: usize,
    decider: T,
) -> (
    oneshot::Sender<()>,
    mpsc::Receiver<(Public, Vec<u8>)>,
    mpsc::Sender<SendPair>,
) {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (incoming_tx, incoming_rx) = mpsc::channel(buffer_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(buffer_size);
    let read_fut = read_into_sender(
        pubkey,
        cipher.clone(),
        max_header_len,
        max_data_len,
        read_half,
        incoming_tx,
        decider,
    );
    let write_fut = write_from_receiver(cipher.clone(), write_half, outgoing_rx);
    tokio::spawn(async {
        tokio::select! {
            _ = read_fut => (),
            _ = write_fut => (),
            _ = cancel_rx => (),
        }
    });

    (cancel_tx, incoming_rx, outgoing_tx)
}

#[derive(Debug)]
enum ReadFutError {
    Read(io::Error),
    Decryption(aead::Error),
    InvalidLen(<usize as TryFrom<u32>>::Error),
    Parse(message::Error),
    Send(SendError<(Public, Vec<u8>)>),
    HeaderTooBig,
    DataTooBig,
    UnrequestedSyn,
}

impl From<io::Error> for ReadFutError {
    fn from(e: io::Error) -> Self {
        ReadFutError::Read(e)
    }
}

impl From<aead::Error> for ReadFutError {
    fn from(e: aead::Error) -> Self {
        ReadFutError::Decryption(e)
    }
}

impl From<std::num::TryFromIntError> for ReadFutError {
    fn from(e: std::num::TryFromIntError) -> Self {
        ReadFutError::InvalidLen(e)
    }
}

impl From<message::Error> for ReadFutError {
    fn from(e: message::Error) -> Self {
        ReadFutError::Parse(e)
    }
}

impl From<SendError<(Public, Vec<u8>)>> for ReadFutError {
    fn from(e: SendError<(Public, Vec<u8>)>) -> Self {
        ReadFutError::Send(e)
    }
}

async fn read_into_sender<R: AsyncReadExt + Unpin, T: SynDecider>(
    pubkey: Public,
    cipher: Aes256Gcm,
    max_header_len: usize,
    max_data_len: usize,
    mut reader: R,
    mut sender: mpsc::Sender<(Public, Vec<u8>)>,
    mut decider: T,
) -> Result<(), ReadFutError> {
    use ReadFutError::*;
    // TODO(ross): What should the size of this buffer be?
    let mut buf = [0u8; 1024];
    loop {
        let l = reader.read_u32().await?;
        let l = usize::try_from(l)?;
        if l > max_header_len {
            // TODO(ross): Should we return more error information?
            return Err(HeaderTooBig);
        }
        let enc_buf = &mut buf[..l];
        let _ = reader.read_exact(enc_buf).await?;
        let res = encode::decrypt_aes256gcm(&cipher, enc_buf)?;
        let header = Message::from_bytes(res)?;
        if header.variant == Variant::Syn {
            if !decider.accept_syn(&header) {
                return Err(UnrequestedSyn);
            }
            let l = reader.read_u32().await?;
            let l = usize::try_from(l)?;
            if l > max_data_len {
                return Err(DataTooBig);
            }
            let enc_buf = &mut buf[..l];
            let _ = reader.read_exact(enc_buf).await?;
            let res = encode::decrypt_aes256gcm(&cipher, enc_buf)?;
            sender.send((pubkey, res)).await?;
        } else {
            sender.send((pubkey, header.data)).await?;
        }
    }
}

#[derive(Debug)]
pub enum WriteError {
    Write(io::Error),
    Encryption(aead::Error),
}

impl From<io::Error> for WriteError {
    fn from(e: io::Error) -> Self {
        WriteError::Write(e)
    }
}

impl From<aead::Error> for WriteError {
    fn from(e: aead::Error) -> Self {
        WriteError::Encryption(e)
    }
}

pub type SendPair = (Message, oneshot::Sender<Result<(), WriteError>>);

async fn write_from_receiver(
    cipher: Aes256Gcm,
    mut write_half: OwnedWriteHalf,
    mut receiver: mpsc::Receiver<SendPair>,
) {
    while let Some((msg, responder)) = receiver.recv().await {
        let msg = msg.to_bytes();
        let mut buf = vec![0u8; 4 + aes256gcm_encrypted_len!(msg.len())];
        let response = match encode::length_and_aes_encode(&mut buf, &msg, &cipher) {
            Ok(()) => write_half.write_all(&buf).await.map_err(WriteError::Write),
            Err(e) => Err(WriteError::from(e)),
        };
        responder.send(response).ok();
    }
}

pub struct Connection {
    reader: Option<mpsc::Receiver<(Public, Vec<u8>)>>,
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
    pub fn new<T: SynDecider + Send + 'static>(
        key: [u8; 32],
        pubkey: Public,
        max_header_len: usize,
        max_data_len: usize,
        buffer_size: usize,
        stream: TcpStream,
        decider: T,
    ) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        let (read_half, write_half) = stream.into_split();
        let (cancel, incoming, outgoing) = new_encrypted_connection_task(
            read_half,
            write_half,
            pubkey,
            cipher,
            max_header_len,
            max_data_len,
            buffer_size,
            decider,
        );
        Self {
            reader: Some(incoming),
            writer: ConnectionWriter::new(outgoing),
            cancel,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.cancel.is_closed()
    }

    pub fn cancel(self) {
        self.cancel.send(()).ok();
    }

    pub fn writer(&self) -> ConnectionWriter {
        self.writer.clone()
    }

    pub async fn write(&mut self, msg: Message) -> Result<(), ConnectionWriteError> {
        self.writer.write(msg).await
    }

    pub fn drain_into(&mut self, mut sink: mpsc::Sender<(Public, Vec<u8>)>) -> bool {
        match self.reader.take() {
            Some(mut reader) => {
                tokio::spawn(async move {
                    while let Some(msg) = reader.recv().await {
                        if sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
                true
            }
            None => false,
        }
    }
}

#[derive(Debug)]
pub enum ConnectionWriteError {
    Send(SendError<SendPair>),
    Receive(RecvError),
    Write(io::Error),
    Encryption(aead::Error),
}

impl From<SendError<SendPair>> for ConnectionWriteError {
    fn from(e: SendError<SendPair>) -> Self {
        ConnectionWriteError::Send(e)
    }
}

impl From<RecvError> for ConnectionWriteError {
    fn from(e: RecvError) -> Self {
        ConnectionWriteError::Receive(e)
    }
}

impl From<WriteError> for ConnectionWriteError {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::Write(e) => ConnectionWriteError::Write(e),
            WriteError::Encryption(e) => ConnectionWriteError::Encryption(e),
        }
    }
}

#[derive(Clone)]
pub struct ConnectionWriter {
    writer: mpsc::Sender<(Message, oneshot::Sender<Result<(), WriteError>>)>,
}

impl ConnectionWriter {
    fn new(writer: mpsc::Sender<SendPair>) -> Self {
        Self { writer }
    }

    pub async fn write(&mut self, msg: Message) -> Result<(), ConnectionWriteError> {
        let (responder, response) = oneshot::channel();
        self.writer.send((msg, responder)).await?;
        response.await?.map_err(ConnectionWriteError::from)
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
        let decision_ser = if own_decision { 1 } else { 0 };
        let enc = encode::encrypt_aes256gcm(cipher, &[decision_ser]).map_err(Error::Encryption)?;
        stream.write_all(&enc).await.map_err(Error::Write)?;
        Ok(own_decision)
    } else {
        let mut buf = [0u8; aes256gcm_encrypted_len!(1)];
        stream.read_exact(&mut buf).await.map_err(Error::Read)?;
        let dec = encode::decrypt_aes256gcm(cipher, &buf).map_err(Error::Decryption)?;
        assert_eq!(dec.len(), 1);
        Ok(dec[0] == 1)
    }
}

pub trait SynDecider {
    fn accept_syn(&mut self, header: &Message) -> bool;
}

pub struct ConnectionPool<T> {
    max_connections: usize,
    max_header_len: usize,
    max_data_len: usize,
    buffer_size: usize,
    connections: HashMap<SocketAddr, Connection>,
    reads_ref: mpsc::Sender<(Public, Vec<u8>)>,
    decider: T,
}

#[derive(Debug)]
pub enum PoolError {
    TooManyConnections,
    PeerAddr(std::io::Error),
}

impl<T: SynDecider + Clone + Send + 'static> ConnectionPool<T> {
    pub fn new_with_max_connections_allocated(
        max_connections: usize,
        max_header_len: usize,
        max_data_len: usize,
        buffer_size: usize,
        decider: T,
    ) -> (Self, mpsc::Receiver<(Public, Vec<u8>)>) {
        let connections = HashMap::with_capacity(max_connections);
        let (tx, rx) = mpsc::channel(buffer_size);
        (
            Self {
                max_connections,
                max_header_len,
                max_data_len,
                buffer_size,
                connections,
                reads_ref: tx,
                decider,
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
        let mut conn = Connection::new(
            key,
            pubkey,
            self.max_header_len,
            self.max_data_len,
            self.buffer_size,
            stream,
            self.decider.clone(),
        );
        let not_drained = conn.drain_into(self.reads_ref.clone());
        assert!(not_drained);
        Ok(self.connections.insert(peer_addr, conn))
    }

    // NOTE(ross): Currently this could be called while another task is writing to the connection,
    // which may not necessarily cause a panic or anything but would probably be unexpected
    // behvaviour.
    pub fn remove_connection(&mut self, addr: &SocketAddr) {
        self.connections.remove(addr).map(Connection::cancel);
    }

    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn is_full(&self) -> bool {
        self.num_connections() >= self.max_connections
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &Connection)> {
        self.connections
            .iter()
            .filter(|(_, conn)| !conn.is_closed())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut Connection)> {
        self.clean_up_pool();
        self.connections.iter_mut()
    }

    pub fn get_connection_mut(&mut self, addr: &SocketAddr) -> Option<&mut Connection> {
        self.clean_up_connection(addr);
        self.connections.get_mut(addr)
    }

    pub fn clean_up_connection(&mut self, addr: &SocketAddr) -> bool {
        if self
            .connections
            .get(addr)
            .map(Connection::is_closed)
            .unwrap_or(false)
        {
            self.remove_connection(addr);
            true
        } else {
            false
        }
    }

    pub fn clean_up_pool(&mut self) {
        self.connections.retain(|_, conn| !conn.is_closed());
    }
}
