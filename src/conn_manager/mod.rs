use crate::conn_manager::connection::Connection;
use crate::handshake;
use crate::util::{self, SharedPtr};
use aes_gcm::aead::{generic_array::GenericArray, NewAead};
use parity_crypto::publickey::{KeyPair, Public};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;

pub mod connection;
pub mod peer_table;

use connection::ConnectionPool;
use peer_table::PeerTable;

pub struct ConnectionManager {
    pool: ConnectionPool,
    table: PeerTable,
}

impl ConnectionManager {
    pub fn new(pool: ConnectionPool, table: PeerTable) -> Self {
        Self { pool, table }
    }

    pub fn add_peer(&mut self, pubkey: Public, addr: SocketAddr) {
        self.table.add_peer(pubkey, addr);
    }
}

pub async fn try_send_peer(
    conn_manager: &SharedPtr<ConnectionManager>,
    peer: &Public,
    msg: &[u8],
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

pub async fn send_to_all(
    conn_manager: &SharedPtr<ConnectionManager>,
    msg: &[u8],
) -> Result<(), Error> {
    let mut writers = {
        let conn_manager_lock = util::get_lock(conn_manager);
        conn_manager_lock
            .pool
            .iter()
            .map(|(_, conn)| conn.writer())
            .collect::<Vec<_>>()
    };
    // TODO(ross): This fails when any of the sends didn't succeed, but in practice for a gossip
    // style execution we will only care if at least a certain number of peers are reached.
    futures::future::try_join_all(writers.iter_mut().map(|writer| writer.write(&msg)))
        .await
        .map(drop)
        .map_err(Error::Connection)
}

#[derive(Debug)]
pub enum Error {
    Handshake(handshake::Error),
    Connection(connection::Error),
    Pool(connection::PoolError),
    Tcp(tokio::io::Error),
    PubKeyMismatch,
    ConnectionDoesNotExist,
}

pub async fn establish_connection<'a>(
    conn_manager: &'a SharedPtr<ConnectionManager>,
    keypair: &KeyPair,
    peer_pubkey: &Public,
    addr: SocketAddr,
) -> Result<(), Error> {
    use Error::*;

    let mut backoff = Duration::from_secs(1);
    loop {
        let conn_manager_lock = match conn_manager.lock() {
            Ok(lock) => lock,
            Err(e) => e.into_inner(),
        };
        if conn_manager_lock
            .table
            .connection_exists_for_peer(peer_pubkey)
        {
            return Ok(());
        }
        if conn_manager_lock.pool.is_full() {
            // TODO(ross): Here we might need to consider the policy we take if the connection
            // pool is full. For example, we might want to be aggressive about establishing the
            // connection and remove an old connection so that the new one can fit.
            todo!()
        }

        // Don't hold the lock during the handshake.
        drop(conn_manager_lock);

        // FIXME(ross): Since we no longer hold the lock, it is possible that another user will
        // initiate another handshake, which can lead to there being two open connections for the
        // one peer.

        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let (key, server_pubkey) = handshake::client_handshake(&mut stream, keypair)
                    .await
                    .map_err(Handshake)?;
                if &server_pubkey != peer_pubkey {
                    // FIXME(ross): This currently completes the entire handshake to find out that
                    // the connection has the wrong pubkey. This can be detected much earlier in
                    // the handshake, and so we should do that and abort early.
                    return Err(PubKeyMismatch);
                }
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
                // TODO(ross): Should we log the error from failing to connect?
                tokio::time::delay_for(backoff).await;
                backoff = backoff.mul_f32(1.6);
            }
        }
    }
}

pub async fn listen_for_peers(
    conn_manager: SharedPtr<ConnectionManager>,
    keypair: KeyPair,
    addr: IpAddr,
    port: u16,
) -> Result<(), Error> {
    use Error::*;

    let mut listener = TcpListener::bind(SocketAddr::new(addr, port))
        .await
        .map_err(Tcp)?;
    while let Some(stream) = listener.incoming().next().await {
        match stream {
            Ok(mut stream) => {
                let keypair = keypair.clone();
                let conn_manager = conn_manager.clone();
                tokio::spawn(async move {
                    println!("[listener] incoming connection, starting handshake");
                    match handshake::server_handshake(&mut stream, &keypair).await {
                        Ok((key, client_pubkey)) => {
                            println!("[listener] successful handhsake");
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
                        Err(e) => {
                            // TODO(ross): Should we log failed handshake attempts?
                            println!("[listener] handshake failed: {:?}", e);
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

async fn add_to_pool_with_reuse(
    conn_manager: SharedPtr<ConnectionManager>,
    mut stream: TcpStream,
    own_pubkey: &Public,
    peer_pubkey: Public,
    key: [u8; 32],
) -> Result<Option<Connection>, Error> {
    let (own_decision, cipher) = {
        let conn_manager_lock = match conn_manager.lock() {
            Ok(lock) => lock,
            Err(e) => e.into_inner(),
        };
        let own_decision = !conn_manager_lock.table.has_peer(&peer_pubkey);
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        (own_decision, cipher)
        // Drop the lock.
    };
    let keep_alive =
        connection::keep_alive(&mut stream, &cipher, own_pubkey, &peer_pubkey, own_decision)
            .await
            .map_err(Error::Connection)?;
    let mut conn_manager_lock = match conn_manager.lock() {
        Ok(lock) => lock,
        Err(e) => e.into_inner(),
    };
    if keep_alive {
        println!("decided to keep alive!");
        println!(
            "adding to pool: {}",
            parity_crypto::publickey::public_to_address(&peer_pubkey),
        );
        let addr = stream.peer_addr().expect("TODO");
        conn_manager_lock.table.add_peer(peer_pubkey, addr);
        conn_manager_lock
            .pool
            .add_connection(stream, peer_pubkey, key)
            .map_err(Error::Pool)
    } else {
        println!("decided to drop!");
        // TODO(ross): Should we signal in the return value that the connection was dropped?
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connection::ConnectionPool;
    use parity_crypto::publickey::{Generator, Random};
    use peer_table::PeerTable;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn existing_connection_is_used() {
        std::thread::spawn(|| {
            let listener = std::net::TcpListener::bind("0.0.0.0:23456").unwrap();
            listener.accept().unwrap();
            loop {}
        });

        let port = 23456;
        let (mut pool, _) = ConnectionPool::new_with_max_connections_allocated(10);
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
