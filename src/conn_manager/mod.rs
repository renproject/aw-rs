use crate::handshake;
use crate::util::SharedPtr;
use parity_crypto::publickey::{KeyPair, Public};
use std::net::{IpAddr, SocketAddr};
use std::sync::MutexGuard;
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

    pub fn add_peer(&mut self, pubkey: &Public, addr: SocketAddr) {
        self.table
            .add_peer(peer_table::id_from_pubkey(pubkey), addr);
    }
}

pub async fn send_to_all(
    conn_manager: &SharedPtr<ConnectionManager>,
    msg: &[u8],
) -> Result<(), Error> {
    let mut conn_manager_lock = match conn_manager.lock() {
        Ok(lock) => lock,
        Err(e) => e.into_inner(),
    };
    for (addr, conn) in conn_manager_lock.pool.iter_mut() {
        if let Some(mut writer) = conn.take_writer() {
            let conn_manager = conn_manager.clone();
            let addr = addr.clone();
            let msg = msg.to_owned();
            tokio::spawn(async move {
                writer.write_all(&msg).await.expect("TODO");
                let mut conn_manager_lock = match conn_manager.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                let conn = conn_manager_lock.pool.get_conn_mut(&addr).expect("TODO");
                conn.give_back_writer(writer);
            });
        }
    }
    Ok(())
}

pub struct ConnectionGuard<'a> {
    addr: SocketAddr,
    guard: MutexGuard<'a, ConnectionManager>,
}

impl<'a> ConnectionGuard<'a> {
    pub async fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.guard
            .pool
            .get_conn_mut(&self.addr)
            .expect("connection should exist")
            .write(msg)
            .await
            .map_err(Error::Connection)
    }
}

#[derive(Debug)]
pub enum Error {
    Handshake(handshake::Error),
    Connection(connection::Error),
    Pool(connection::PoolError),
    Tcp(tokio::io::Error),
    PubKeyMismatch,
}

pub async fn get_connection_or_establish<'a>(
    conn_manager: &'a SharedPtr<ConnectionManager>,
    keypair: &KeyPair,
    peer_pubkey: &Public,
    addr: SocketAddr,
) -> Result<ConnectionGuard<'a>, Error> {
    use Error::*;

    let mut backoff = Duration::from_secs(1);
    let id = peer_table::id_from_pubkey(peer_pubkey);
    loop {
        let conn_manager_lock = match conn_manager.lock() {
            Ok(lock) => lock,
            Err(e) => e.into_inner(),
        };
        if conn_manager_lock.table.connection_exists_for_peer(&id) {
            return Ok(ConnectionGuard {
                addr,
                guard: conn_manager_lock,
            });
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
                let mut conn_manager_lock = match conn_manager.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                conn_manager_lock
                    .pool
                    .add_connection(stream, *peer_pubkey, key)
                    .map(drop)
                    .map_err(Pool)?;
                return Ok(ConnectionGuard {
                    addr,
                    guard: conn_manager_lock,
                });
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
                            let mut conn_manager_lock = match conn_manager.lock() {
                                Ok(lock) => lock,
                                Err(e) => e.into_inner(),
                            };
                            let id = peer_table::id_from_pubkey(&client_pubkey);
                            let addr = stream.peer_addr().expect("TODO");
                            conn_manager_lock.table.add_peer(id, addr);
                            match conn_manager_lock
                                .pool
                                .add_connection(stream, client_pubkey, key)
                            {
                                Ok(replaced) => {
                                    if let Some(_replaced) = replaced {
                                        // TODO(ross): Do we want to create logs when replacing
                                        // duplicate connections?
                                    }
                                    println!("[listener] connection added to pool");
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
