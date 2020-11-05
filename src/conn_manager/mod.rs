use crate::conn_manager::connection::Connection;
use crate::handshake;
use crate::message::Message;
use crate::util::{self, SharedPtr};
use aes_gcm::aead::{generic_array::GenericArray, NewAead};
use parity_crypto::publickey::{KeyPair, Public};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;

pub mod connection;
pub mod peer_table;

use connection::{ConnectionPool, SynDecider};
use peer_table::PeerTable;

pub struct ConnectionManager<T> {
    pool: ConnectionPool<T>,
    table: PeerTable,
}

impl<T> ConnectionManager<T> {
    pub fn new(pool: ConnectionPool<T>, table: PeerTable) -> Self {
        Self { pool, table }
    }

    pub fn add_peer(&mut self, pubkey: Public, addr: SocketAddr) {
        self.table.add_peer(pubkey, addr);
    }

    pub fn num_peers(&self) -> usize {
        self.table.num_peers()
    }

    pub fn peers(&self) -> impl Iterator<Item = (&Public, &SocketAddr)> {
        self.table.peers()
    }

    pub fn random_peer_subset(&self, n: usize) -> Vec<Public> {
        self.table.random_peer_subset(n)
    }
}

pub async fn try_send_peer<T: SynDecider + Clone + Send + 'static>(
    conn_manager: &SharedPtr<ConnectionManager<T>>,
    peer: &Public,
    msg: Message,
) -> Result<(), Error> {
    let writer = {
        let mut conn_manager_lock = util::get_lock(conn_manager);
        conn_manager_lock
            .table
            .peer_addr(peer)
            .cloned()
            .and_then(|addr| {
                conn_manager_lock
                    .pool
                    .get_connection_mut(&addr)
                    .map(|conn| conn.writer())
            })
    };
    if let Some(mut writer) = writer {
        writer.write(msg).await.map_err(Error::Connection)
    } else {
        Err(Error::ConnectionDoesNotExist)
    }
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
) -> Result<(), Error> {
    let mut backoff = Duration::from_secs(1);
    loop {
        {
            let conn_manager = util::get_lock(&conn_manager);
            if conn_manager.table.connection_exists_for_peer(peer_pubkey) {
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
                    handshake::client_handshake(&mut stream, keypair, Some(peer_pubkey)).await?;
                return add_to_pool_with_reuse(
                    conn_manager.clone(),
                    stream,
                    keypair.public(),
                    server_pubkey,
                    key,
                )
                .await
                .map(drop);
            }
            Err(_e) => {
                tokio::time::delay_for(backoff).await;
                backoff = backoff.mul_f32(1.6);
            }
        }
    }
}

pub async fn listen_for_peers<T: SynDecider + Clone + Send + 'static>(
    conn_manager: SharedPtr<ConnectionManager<T>>,
    keypair: KeyPair,
    addr: IpAddr,
    port: u16,
) -> Result<(), Error> {
    let mut listener = TcpListener::bind(SocketAddr::new(addr, port))
        .await
        .map_err(Error::Tcp)?;
    while let Some(stream) = listener.incoming().next().await {
        match stream {
            Ok(mut stream) => {
                let keypair = keypair.clone();
                let conn_manager = conn_manager.clone();
                tokio::spawn(async move {
                    match handshake::server_handshake(&mut stream, &keypair).await {
                        Ok((key, client_pubkey)) => {
                            match add_to_pool_with_reuse(
                                conn_manager,
                                stream,
                                keypair.public(),
                                client_pubkey,
                                key,
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

    Ok(())
}

async fn add_to_pool_with_reuse<T: SynDecider + Clone + Send + 'static>(
    conn_manager: SharedPtr<ConnectionManager<T>>,
    mut stream: TcpStream,
    own_pubkey: &Public,
    peer_pubkey: Public,
    key: [u8; 32],
) -> Result<Option<Connection>, Error> {
    let (own_decision, cipher) = {
        let conn_manager = util::get_lock(&conn_manager);
        let own_decision = !conn_manager.table.has_peer(&peer_pubkey);
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
        conn_manager.table.add_peer(peer_pubkey, addr);
        conn_manager
            .pool
            .add_connection(stream, peer_pubkey, key)
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
        let existing_peer = table.add_peer(peer_pubkey, addr);
        assert!(existing_peer.is_none());

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let stream = TcpStream::from_std(stream).unwrap();
        let existing_conn = pool.add_connection(stream, *keypair.public(), key).unwrap();
        assert!(existing_conn.is_none());

        let conn_manager = ConnectionManager::new(pool, table);
        let conn_manager = Arc::new(Mutex::new(conn_manager));

        futures::executor::block_on(establish_connection(
            &conn_manager,
            &keypair,
            &peer_pubkey,
            addr,
        ))
        .unwrap();
        let conn_manager = util::get_lock(&conn_manager);
        assert_eq!(conn_manager.pool.num_connections(), 1);
    }
}
