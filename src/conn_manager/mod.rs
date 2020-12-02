use crate::conn_manager::connection::{Connection, ConnectionWriter};
use crate::handshake;
use crate::message::Message;
use crate::rate::{self, BoundedUniformLimiterMap};
use crate::util::{self, SharedPtr};
use aes_gcm::aead::{generic_array::GenericArray, NewAead};
use futures::Future;
use parity_crypto::publickey::{KeyPair, Public};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::time;

pub mod connection;
pub mod peer_table;

use connection::{ConnectionPool, SynDecider};
use peer_table::{PeerTable, SignedAddress};

pub struct ConnectionManager<T> {
    pool: ConnectionPool<T>,
    table: PeerTable,
}

impl<T> ConnectionManager<T> {
    pub fn new(pool: ConnectionPool<T>, table: PeerTable) -> Self {
        Self { pool, table }
    }

    pub fn add_unsigned_peer(&mut self, pubkey: Public, addr: SocketAddr) {
        self.table.add_unsigned_peer(pubkey, addr);
    }

    pub fn add_signed_peer(&mut self, pubkey: Public, addr: SignedAddress) {
        self.table.add_signed_peer(pubkey, addr);
    }

    pub fn num_peers(&self) -> usize {
        self.table.num_peers()
    }

    pub fn unsigned_peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.table.unsigned_peers()
    }

    pub fn signed_peers(&self) -> impl Iterator<Item = (&Public, &SignedAddress)> {
        self.table.signed_peers()
    }

    pub fn peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.table.peers()
    }

    pub fn random_peer_subset(&self, n: usize) -> Vec<Public> {
        self.table.random_peer_subset(n)
    }

    pub fn random_signed_address_subset(&self, n: usize) -> Vec<SignedAddress> {
        self.table.random_signed_address_subset(n)
    }

    pub fn has_connection_to_peer(&self, pubkey: &Public) -> bool {
        let addr = self.table.peer_socket_addr(pubkey);
        addr.map(|addr| self.pool.has_connection(addr))
            .unwrap_or(false)
    }

    pub fn peer_connection(&mut self, pubkey: &Public) -> Option<ConnectionWriter> {
        self.table
            .peer_socket_addr(pubkey)
            .cloned()
            .and_then(|addr| self.pool.get_connection(&addr).map(Connection::writer))
    }
}

pub async fn try_send_peer<T: SynDecider + Clone + Send + 'static>(
    conn_manager: &SharedPtr<ConnectionManager<T>>,
    peer: &Public,
    msg: Message,
) -> Result<(), Error> {
    let writer = {
        let mut conn_manager_lock = util::get_lock(conn_manager);
        conn_manager_lock.peer_connection(peer)
    };
    if let Some(mut writer) = writer {
        writer.write(msg).await.map_err(Error::Connection)
    } else {
        Err(Error::ConnectionDoesNotExist)
    }
}

pub async fn send_with_establish<T: SynDecider + Clone + Send + 'static>(
    conn_manager: &SharedPtr<ConnectionManager<T>>,
    keypair: &KeyPair,
    peer: &Public,
    msg: Message,
    ttl: Option<Duration>,
    initial_backoff: Duration,
    backoff_multiplier: f64,
) -> Result<(), Error> {
    let (addr, maybe_writer) = {
        let mut conn_manager = conn_manager.lock().unwrap();
        let addr = conn_manager
            .table
            .peer_socket_addr(peer)
            .cloned()
            .ok_or(Error::PeerDoesNotExist)?;

        let maybe_writer = conn_manager
            .pool
            .get_connection(&addr)
            .map(Connection::writer);
        (addr, maybe_writer)
    };

    let mut writer = match maybe_writer {
        None => {
            // TODO(ross): Do we want to have a timeout for the completion of this future? The
            // caller of the function can put a timeout on the whole call, but maybe being able to
            // set a timeout for this specific part is more useful.
            establish_connection(conn_manager, keypair, peer, addr, ttl).await?;

            // TODO(ross): Since we have just returned from establishing a connection, we expect
            // that a connection for this peer should exist. This will be true in the vast majority
            // of cases, but is not always necessarily true. Some ways in which this could happen
            // are:
            //      - No connection was existing but we receive a drop signal during the connection
            //      duplication procedure. This could be due to a malicious peer or simultaneous
            //      handshakes (the peer would send both a keep alive and a drop signal, but the
            //      latter may arrive first).
            //      - The connection existed but was dropped just after returning from above. This
            //      could be caused by a task explicitly closing the connection, or the connection
            //      either naturally expiring or being closed by the connection logic.
            // To attempt to account for this possibility, we retry getting the connection for the
            // peer from the peer table with a backoff. This resolves the former situation with a
            // non-malicious peer, but does not resolve the others. How should we account for these
            // other cases? For now the user of the function should call this method with a timeou
            // if they are worried about these other cases ocurring.
            let mut backoff = initial_backoff;
            loop {
                {
                    let mut conn_manager = conn_manager.lock().unwrap();
                    if let Some(writer) = conn_manager.peer_connection(peer) {
                        break writer;
                    }
                }
                time::delay_for(backoff).await;
                backoff = backoff.mul_f64(backoff_multiplier);
            }
        }
        Some(writer) => writer,
    };

    writer.write(msg).await.map_err(Error::Connection)
}

#[derive(Debug)]
pub enum Error {
    Handshake(handshake::Error),
    Connection(connection::ConnectionWriteError),
    Pool(connection::PoolError),
    Tcp(tokio::io::Error),
    KeepAlive(connection::Error),
    PubKeyMismatch,
    ConnectionDoesNotExist,
    PeerDoesNotExist,
}

impl From<handshake::Error> for Error {
    fn from(e: handshake::Error) -> Error {
        Error::Handshake(e)
    }
}

pub async fn establish_connection<'a, T: SynDecider + Clone + Send + 'static>(
    conn_manager: &'a SharedPtr<ConnectionManager<T>>,
    keypair: &KeyPair,
    peer_pubkey: &Public,
    addr: SocketAddr,
    ttl: Option<Duration>,
) -> Result<(), Error> {
    // TODO(ross): This should probably be configurable by the user.
    let mut backoff = Duration::from_secs(1);
    loop {
        {
            let conn_manager = util::get_lock(&conn_manager);
            if conn_manager.pool.has_connection(&addr) {
                return Ok(());
            }
            if conn_manager.pool.is_full() {
                // TODO(ross): Here we might need to consider the policy we take if the connection pool
                // is full. For example, we might want to be aggressive about establishing the
                // connection and remove an old connection so that the new one can fit.
                todo!()
            }
        } // Don't hold the lock during the handshake.

        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let (key, server_pubkey) =
                    handshake::handshake(&mut stream, keypair, Some(peer_pubkey)).await?;
                let ret = add_to_pool_with_reuse(
                    conn_manager.clone(),
                    stream,
                    keypair.public(),
                    server_pubkey,
                    key,
                    ttl,
                )
                .await
                .map(drop);
                if ret.is_ok() {
                } else {
                }
                return ret;
            }
            Err(_e) => {
                tokio::time::delay_for(backoff).await;
                backoff = backoff.mul_f32(1.6);
            }
        }
    }
}

pub fn listen_for_peers<T: SynDecider + Clone + Send + 'static>(
    conn_manager: SharedPtr<ConnectionManager<T>>,
    keypair: KeyPair,
    addr: IpAddr,
    port: u16,
    rate_limiter_options: rate::Options,
) -> Result<(u16, impl Future<Output = ()>), io::Error> {
    // NOTE(ross): Here we block on binding the listener, because when binding to a socket address
    // (or more specifically an address that doesn't require a DNS lookup) the call should complete
    // immediately, and we want to be able to immediately return the port in case the given port
    // was 0 (in which case the actual port will be randomly assigned).
    let mut listener = futures::executor::block_on(TcpListener::bind(SocketAddr::new(addr, port)))?;
    let port = listener.local_addr()?.port();
    let mut rate_limter = BoundedUniformLimiterMap::new(rate_limiter_options);

    let fut = async move {
        while let Some(stream) = listener.incoming().next().await {
            match stream {
                Ok(mut stream) => {
                    // Rate limiting based on IP address.
                    let ip_addr = match stream.local_addr() {
                        Ok(addr) => addr,
                        Err(_e) => todo!("what does this error mean?"),
                    }
                    .ip();
                    if !rate_limter.allow(ip_addr) {
                        continue;
                    }

                    let keypair = keypair.clone();
                    let conn_manager = conn_manager.clone();
                    tokio::spawn(async move {
                        match handshake::handshake(&mut stream, &keypair, None).await {
                            Ok((key, client_pubkey)) => {
                                match add_to_pool_with_reuse(
                                    conn_manager,
                                    stream,
                                    keypair.public(),
                                    client_pubkey,
                                    key,
                                    // TODO(ross): For now any connections that peers establish
                                    // with us will be long lived, but this is not likely to be the
                                    // common case. In general, we will probably want to have some
                                    // logic about what kind of connection to establish that may
                                    // come from the user application.
                                    None,
                                )
                                .await
                                {
                                    Ok(replaced) => {
                                        if let Some(_replaced) = replaced {
                                            // TODO(ross): Do we want to create logs when replacing
                                            // duplicate connections?
                                        }
                                    }
                                    Err(_e) => {
                                        // TODO(ross): What to do when the pool is full?
                                    }
                                }
                            }
                            Err(_e) => {
                                // TODO(ross): Should we log failed handshake attempts?
                            }
                        }
                    });
                }
                Err(_e) => {
                    // TODO(ross): Do we want to log this?
                }
            }
        }
    };

    Ok((port, fut))
}

async fn add_to_pool_with_reuse<T: SynDecider + Clone + Send + 'static>(
    conn_manager: SharedPtr<ConnectionManager<T>>,
    mut stream: TcpStream,
    own_pubkey: &Public,
    peer_pubkey: Public,
    key: [u8; 32],
    ttl: Option<Duration>,
) -> Result<Option<Connection>, Error> {
    let (own_decision, cipher) = {
        let conn_manager = util::get_lock(&conn_manager);
        let own_decision = conn_manager
            .table
            .peer_socket_addr(&peer_pubkey)
            .map(|addr| !conn_manager.pool.has_connection(addr))
            .unwrap_or(true);
        // let own_decision = !conn_manager.table.has_peer(&peer_pubkey);
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        (own_decision, cipher)
    }; // Drop the lock.
    let keep_alive =
        connection::keep_alive(&mut stream, &cipher, own_pubkey, &peer_pubkey, own_decision)
            .await
            .map_err(Error::KeepAlive)?;
    let mut conn_manager = util::get_lock(&conn_manager);
    if keep_alive {
        let addr = stream.peer_addr().expect("TODO");
        conn_manager.table.add_unsigned_peer(peer_pubkey, addr);
        conn_manager
            .pool
            .add_connection(stream, peer_pubkey, key, ttl)
            .map_err(Error::Pool)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::Decider;
    use connection::ConnectionPool;
    use parity_crypto::publickey::{Generator, Random};
    use peer_table::PeerTable;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn existing_connection_is_used() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            listener.accept().unwrap();
            loop {}
        });

        let (mut pool, _) =
            ConnectionPool::new_with_max_connections_allocated(10, 256, 256, 100, Decider::new());
        let mut table = PeerTable::new();
        let keypair = Random.generate();
        let peer_pubkey = *Random.generate().public();
        let key = rand::random();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        let existing_peer = table.add_unsigned_peer(peer_pubkey, addr);
        assert!(existing_peer.is_none());

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let stream = TcpStream::from_std(stream).unwrap();
        let existing_conn = pool
            .add_connection(stream, *keypair.public(), key, None)
            .unwrap();
        assert!(existing_conn.is_none());

        let conn_manager = ConnectionManager::new(pool, table);
        let conn_manager = Arc::new(Mutex::new(conn_manager));

        futures::executor::block_on(establish_connection(
            &conn_manager,
            &keypair,
            &peer_pubkey,
            addr,
            None,
        ))
        .unwrap();
        let conn_manager = util::get_lock(&conn_manager);
        assert_eq!(conn_manager.pool.num_connections(), 1);
    }
}
