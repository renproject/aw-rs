use crate::conn_manager::peer_table;
use crate::message::{self, Header, Message, Variant};
use aes_gcm::aead::{self, generic_array::GenericArray, NewAead};
use aes_gcm::Aes256Gcm;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::num::TryFromIntError;
use std::time::{Duration, Instant};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{
    mpsc::{self, error::SendError},
    oneshot::{self, error::RecvError},
};
use tokio::time;

#[macro_use]
mod encode;

use encode::{NONCE_SIZE, TAG_SIZE};

enum TTLOrCancel {
    TTL(Duration),
    Cancel,
}

fn new_encrypted_connection_task<T: SynDecider + Send + 'static>(
    stream: TcpStream,
    pubkey: Public,
    cipher: Aes256Gcm,
    ttl: Option<Duration>,
    max_header_len: usize,
    max_data_len: usize,
    buffer_size: usize,
    decider: T,
) -> (
    oneshot::Sender<()>,
    mpsc::Sender<TTLOrCancel>,
    mpsc::Receiver<(Public, Message)>,
    mpsc::Sender<SendPair>,
) {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (mut timeout_cancel_tx, timeout_cancel_rx) = oneshot::channel();
    let (incoming_tx, incoming_rx) = mpsc::channel(buffer_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(buffer_size);
    let (timeout_tx, mut timeout_rx) = mpsc::channel(buffer_size);
    let (read_half, write_half) = stream.into_split();
    let read_fut = read_into_sender(
        pubkey,
        cipher.clone(),
        max_header_len,
        max_data_len,
        read_half,
        incoming_tx,
        decider,
    );
    let write_fut = write_from_receiver(cipher, write_half, outgoing_rx);
    let fut = async {
        tokio::select! {
            _ = read_fut => (),
            _ = write_fut => (),
            _ = cancel_rx => (),
            // NOTE(ross): I think that the only time that a one shot result will be an error is if
            // the sender has been dropped/closed. In our context, this means that the time out is
            // no longer relevant, and so we don't want the select to complete in this case.
            Ok(_) = timeout_cancel_rx => (),
        }
    };
    match ttl {
        Some(ttl) => {
            let mut timeout = time::delay_for(ttl);
            let timeout_fut = async move {
                tokio::pin!(fut);
                let mut enable_timer = true;
                loop {
                    tokio::select! {
                        _ = &mut timeout, if enable_timer => {
                            timeout_cancel_tx.send(()).ok();
                            break;
                        },
                        _ = timeout_cancel_tx.closed() => break,
                        Some(ttl_or_cancel) = timeout_rx.recv() => {
                            match ttl_or_cancel {
                                TTLOrCancel::TTL(dur) => {
                                    match Instant::now().checked_add(dur) {
                                        Some(new_deadline) => {
                                            let new_deadline = tokio::time::Instant::from_std(new_deadline);
                                            if new_deadline > timeout.deadline() {
                                                timeout.reset(new_deadline);
                                            }
                                        },
                                        None => {
                                            // TODO(ross): This occurs when the duration added to
                                            // the current time cannot be represented in the data
                                            // structure, which should probably never happen in our
                                            // code.
                                        }
                                    }
                                }
                                TTLOrCancel::Cancel => {
                                    enable_timer = false;
                                    timeout_rx.close();
                                }
                            }
                        },
                        _ = &mut fut => break,
                    }
                }
            };
            tokio::spawn(timeout_fut);
        }
        None => {
            tokio::spawn(fut);
        }
    }

    (cancel_tx, timeout_tx, incoming_rx, outgoing_tx)
}

#[derive(Debug)]
enum ReadFutError {
    Parse(message::Error),
    Send(SendError<(Public, Message)>),
    Decode(DecodeError),
    UnrequestedSyn,
}

impl From<message::Error> for ReadFutError {
    fn from(e: message::Error) -> Self {
        ReadFutError::Parse(e)
    }
}

impl From<SendError<(Public, Message)>> for ReadFutError {
    fn from(e: SendError<(Public, Message)>) -> Self {
        ReadFutError::Send(e)
    }
}

impl From<DecodeError> for ReadFutError {
    fn from(e: DecodeError) -> Self {
        ReadFutError::Decode(e)
    }
}

async fn read_into_sender<R: AsyncReadExt + Unpin, T: SynDecider>(
    pubkey: Public,
    cipher: Aes256Gcm,
    max_header_len: usize,
    max_data_len: usize,
    mut reader: R,
    mut sender: mpsc::Sender<(Public, Message)>,
    mut decider: T,
) -> Result<(), ReadFutError> {
    use ReadFutError::*;
    // TODO(ross): What should the size of this buffer be?
    let mut buf = [0u8; 1024];
    loop {
        let header_bytes =
            decode_aes_len_encoded(&mut reader, &mut buf, &cipher, max_header_len).await?;
        let header = Header::from_bytes(header_bytes)?;
        if header.variant != Variant::Syn {
            sender.send((pubkey, Message::Header(header))).await?;
        } else {
            if !decider.syn_requested(&header) {
                return Err(UnrequestedSyn);
            }
            let message =
                decode_aes_len_encoded(&mut reader, &mut buf, &cipher, max_data_len).await?;
            sender.send((pubkey, Message::Syn(header, message))).await?;
        }
    }
}

#[derive(Debug)]
enum DecodeError {
    Read(io::Error),
    Decryption(aead::Error),
    InvalidLen(TryFromIntError),
    TooBig,
}

impl From<ReadU32Error> for DecodeError {
    fn from(e: ReadU32Error) -> Self {
        match e {
            ReadU32Error::Read(e) => DecodeError::Read(e),
            ReadU32Error::TooBig => DecodeError::TooBig,
        }
    }
}

impl From<aead::Error> for DecodeError {
    fn from(e: aead::Error) -> Self {
        DecodeError::Decryption(e)
    }
}

impl From<TryFromIntError> for DecodeError {
    fn from(e: TryFromIntError) -> Self {
        DecodeError::InvalidLen(e)
    }
}

impl From<io::Error> for DecodeError {
    fn from(e: io::Error) -> Self {
        DecodeError::Read(e)
    }
}

async fn decode_aes_len_encoded<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    cipher: &Aes256Gcm,
    limit: usize,
) -> Result<Vec<u8>, DecodeError> {
    let l = read_u32_len_with_limit(reader, limit as u32)
        .await?
        .try_into()?;
    let enc_buf = &mut buf[..l];
    let _ = reader.read_exact(enc_buf).await?;
    encode::decrypt_aes256gcm(&cipher, enc_buf).map_err(DecodeError::from)
}

enum ReadU32Error {
    Read(io::Error),
    TooBig,
}

impl From<io::Error> for ReadU32Error {
    fn from(e: io::Error) -> Self {
        ReadU32Error::Read(e)
    }
}

async fn read_u32_len_with_limit<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    limit: u32,
) -> Result<u32, ReadU32Error> {
    let l = reader.read_u32().await?;
    if l > limit {
        Err(ReadU32Error::TooBig)
    } else {
        Ok(l)
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

async fn write_from_receiver<W: AsyncWriteExt + Unpin>(
    cipher: Aes256Gcm,
    mut write_half: W,
    mut receiver: mpsc::Receiver<SendPair>,
) {
    while let Some((msg, responder)) = receiver.recv().await {
        let response = match msg {
            Message::Header(header) => {
                let header = header.to_bytes();
                let mut buf = vec![0u8; 4 + aes256gcm_encrypted_len!(header.len())];
                match encode::length_and_aes_encode(&mut buf, &header, &cipher) {
                    Ok(()) => write_half.write_all(&buf).await.map_err(WriteError::Write),
                    Err(e) => Err(WriteError::from(e)),
                }
            }
            Message::Syn(header, value) => write_syn(&cipher, &mut write_half, header, value).await,
        };
        responder.send(response).ok();
    }
}

async fn write_syn<W: AsyncWriteExt + Unpin>(
    cipher: &Aes256Gcm,
    write_half: &mut W,
    header: Header,
    value: Vec<u8>,
) -> Result<(), WriteError> {
    let header = header.to_bytes();
    let header_enc_len = 4 + aes256gcm_encrypted_len!(header.len());
    let value_enc_len = 4 + aes256gcm_encrypted_len!(value.len());
    let mut buf = vec![0u8; header_enc_len + value_enc_len];
    let (header_buf, value_buf) = buf.split_at_mut(header_enc_len);
    encode::length_and_aes_encode(header_buf, &header, &cipher)?;
    encode::length_and_aes_encode(value_buf, &value, &cipher)?;
    write_half.write_all(&buf).await.map_err(WriteError::Write)
}

pub struct Connection {
    reader: Option<mpsc::Receiver<(Public, Message)>>,
    writer: ConnectionWriter,
    cancel: oneshot::Sender<()>,
    timeout_update: mpsc::Sender<TTLOrCancel>,
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
        ttl: Option<Duration>,
        max_header_len: usize,
        max_data_len: usize,
        buffer_size: usize,
        stream: TcpStream,
        decider: T,
    ) -> Self {
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));

        // Disable the Nagle algorithm for the socket. We do this because otherwise the socket will
        // not send the next message until the previous send has been ACKed, which may be delayed
        // 40ms at the receiver side, not to mention any network delays.
        //
        // NOTE(ross): We are unwrapping this because the error cases expressed in `man 3
        // setsockopt` seem like they would not occurr in a properly functioning system. However,
        // do we want to recover anyway and not set the option?
        stream
            .set_nodelay(true)
            .expect("setting SO_NODELAY for socket");

        let (cancel, timeout_update, incoming, outgoing) = new_encrypted_connection_task(
            stream,
            pubkey,
            cipher,
            ttl,
            max_header_len,
            max_data_len,
            buffer_size,
            decider,
        );
        Self {
            reader: Some(incoming),
            writer: ConnectionWriter::new(outgoing),
            cancel,
            timeout_update,
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

    pub fn update_timeout(&mut self, ttl: Duration) {
        match self.timeout_update.try_send(TTLOrCancel::TTL(ttl)) {
            Ok(_) => (),
            Err(mpsc::error::TrySendError::<TTLOrCancel>::Closed(_)) => {
                // NOTE(ross): In this case the receiver is closed which *should* mean that either
                // the socket is long lived or that the socket is closed.
            }
            Err(mpsc::error::TrySendError::<TTLOrCancel>::Full(_)) => {
                // TODO(ross): In this case the channel buffer is full. This could happen if there
                // are many attempts to update the timeout (unlikely) and the system is under heavy
                // load. This seems like a situation that probably shouldn't occur, but we should
                // think about what a caller of the function might want to do in this case, and if
                // there is something we should return something that will notify the user.
            }
        }
    }

    pub fn make_long_lived(&mut self) -> bool {
        if let Err(mpsc::error::TrySendError::<TTLOrCancel>::Full(_)) =
            self.timeout_update.try_send(TTLOrCancel::Cancel)
        {
            false
        } else {
            true
        }
    }

    pub fn drain_into(&mut self, mut sink: mpsc::Sender<(Public, Message)>) -> bool {
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
    fn syn_requested(&mut self, header: &Header) -> bool;
}

pub struct ConnectionPool<T> {
    max_connections: usize,
    max_header_len: usize,
    max_data_len: usize,
    buffer_size: usize,
    connections: HashMap<SocketAddr, Connection>,
    reads_ref: mpsc::Sender<(Public, Message)>,
    decider: T,
}

#[derive(Debug)]
pub enum PoolError {
    TooManyConnections,
    PeerAddr(std::io::Error),
}

impl<T> ConnectionPool<T> {
    pub fn new_with_max_connections_allocated(
        max_connections: usize,
        max_header_len: usize,
        max_data_len: usize,
        buffer_size: usize,
        decider: T,
    ) -> (Self, mpsc::Receiver<(Public, Message)>) {
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

    // NOTE(ross): Currently this could be called while another task is writing to the connection,
    // which may not necessarily cause a panic or anything but would probably be unexpected
    // behvaviour.
    pub fn remove_connection(&mut self, addr: &SocketAddr) {
        self.connections.remove(addr).map(Connection::cancel);
    }

    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn has_connection(&self, addr: &SocketAddr) -> bool {
        self.connections.contains_key(addr)
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

    pub fn get_connection(&mut self, addr: &SocketAddr) -> Option<&Connection> {
        self.clean_up_connection(addr);
        self.connections.get(addr)
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

impl<T: SynDecider + Clone + Send + 'static> ConnectionPool<T> {
    pub fn add_connection(
        &mut self,
        stream: TcpStream,
        pubkey: Public,
        key: [u8; 32],
        ttl: Option<Duration>,
    ) -> Result<Option<Connection>, PoolError> {
        use PoolError::*;

        if self.connections.len() >= self.max_connections {
            return Err(TooManyConnections);
        }
        let peer_addr = stream.peer_addr().map_err(PeerAddr)?;
        let mut conn = Connection::new(
            key,
            pubkey,
            ttl,
            self.max_header_len,
            self.max_data_len,
            self.buffer_size,
            stream,
            self.decider.clone(),
        );
        let not_drained = conn.drain_into(self.reads_ref.clone());
        assert!(not_drained);
        let ret = Ok(self.connections.insert(peer_addr, conn));
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{GOSSIP_PEER_ID, V1};
    use parity_crypto::publickey::{Generator, Random};
    use tokio::net::TcpListener;

    struct DummyDecider {}

    impl SynDecider for DummyDecider {
        fn syn_requested(&mut self, _: &Header) -> bool {
            true
        }
    }

    async fn default_client_server_connections(
        client_ttl: Option<Duration>,
        server_ttl: Option<Duration>,
    ) -> (Connection, Connection) {
        let max_header_len = 1024;
        let max_data_len = 1024;
        let buffer_size = 100;

        let key = rand::random();
        let (client_keypair, server_keypair) = (Random.generate(), Random.generate());

        let mut listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let client_connection = Connection::new(
            key,
            *client_keypair.public(),
            client_ttl,
            max_header_len,
            max_data_len,
            buffer_size,
            client_stream,
            DummyDecider {},
        );
        let server_connection = Connection::new(
            key,
            *server_keypair.public(),
            server_ttl,
            max_header_len,
            max_data_len,
            buffer_size,
            server_stream,
            DummyDecider {},
        );

        (client_connection, server_connection)
    }

    #[tokio::test]
    async fn short_lived_connections_expire() {
        let ttl = Duration::from_millis(10);
        let (mut client_connection, server_connection) =
            default_client_server_connections(Some(ttl), None).await;

        // Messages should be able to be sent while the connection is open.
        let msg = Message::Header(Header::new(V1, Variant::Push, GOSSIP_PEER_ID, vec![1, 2]));
        client_connection.write(msg.clone()).await.unwrap();
        let (_, received_msg) = server_connection.reader.unwrap().recv().await.unwrap();
        assert_eq!(received_msg, msg);

        // After the TTL has expired, the connection should be closed.
        tokio::time::delay_for(ttl).await;
        assert!(client_connection.is_closed());
    }

    #[tokio::test]
    async fn short_lived_connections_can_be_made_long_lived() {
        let ttl = Duration::from_millis(2);
        let (mut client_connection, server_connection) =
            default_client_server_connections(Some(ttl), None).await;

        // Make the connection long lived.
        assert!(client_connection.make_long_lived());

        // Messages should now be able to be sent after the TTL that was originally set for the
        // short lived connection.
        tokio::time::delay_for(10 * ttl).await;
        assert!(!client_connection.is_closed());
        let msg = Message::Header(Header::new(V1, Variant::Push, GOSSIP_PEER_ID, vec![1, 2]));
        client_connection.write(msg.clone()).await.unwrap();
        let (_, received_msg) = server_connection.reader.unwrap().recv().await.unwrap();
        assert_eq!(received_msg, msg);
    }
}
