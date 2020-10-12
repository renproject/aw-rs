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

use connection::{Connection, ConnectionPool};
use peer_table::PeerTable;

pub struct ConnectionManager {
    pool: ConnectionPool,
    table: PeerTable,
}

impl ConnectionManager {
    pub fn new(pool: ConnectionPool, table: PeerTable) -> Self {
        Self { pool, table }
    }
}

pub async fn get_connection_or_establish<'a>(
    keypair: &KeyPair,
    peer_pubkey: &Public,
    addr: SocketAddr,
    conn_manager: &'a SharedPtr<ConnectionManager>,
) -> Result<ConnectionGuard<'a>, ()> {
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
                let key = handshake::client_handshake(&mut stream, keypair, peer_pubkey)
                    .await
                    .map_err(|_| todo!())?;
                let conn = Connection::new(stream, key);
                let mut conn_manager_lock = match conn_manager.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                conn_manager_lock
                    .pool
                    .add_connection(conn)
                    .map(drop)
                    .map_err(|_| todo!())?;
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
    addr: IpAddr,
    port: u16,
    keypair: KeyPair,
) -> Result<(), ()> {
    let mut listener = TcpListener::bind(SocketAddr::new(addr, port))
        .await
        .map_err(|_| todo!())?;
    while let Some(stream) = listener.incoming().next().await {
        let mut stream = stream.map_err(|_| todo!()).expect("TODO");
        let keypair = keypair.clone();
        let conn_manager = conn_manager.clone();
        tokio::spawn(async move {
            match handshake::server_handshake(&mut stream, &keypair).await {
                Ok((key, client_pubkey)) => {
                    let mut conn_manager_lock = match conn_manager.lock() {
                        Ok(lock) => lock,
                        Err(e) => e.into_inner(),
                    };
                    let id = peer_table::id_from_pubkey(&client_pubkey);
                    let addr = stream.peer_addr().expect("TODO");
                    conn_manager_lock.table.add_peer(id, addr);
                    let conn = Connection::new(stream, key);
                    if let Some(_replaced) =
                        conn_manager_lock.pool.add_connection(conn).expect("TODO")
                    {
                        // TODO(ross): Do we want to create logs when replacing duplicate
                        // connections?
                    }
                }
                Err(_e) => todo!(),
            }
        });
    }

    Ok(())
}

pub struct ConnectionGuard<'a> {
    addr: SocketAddr,
    guard: MutexGuard<'a, ConnectionManager>,
}

impl<'a> ConnectionGuard<'a> {
    pub async fn write(&mut self, msg: &[u8]) -> Result<(), ()> {
        self.guard
            .pool
            .get_conn_mut(&self.addr)
            .expect("connection should exist")
            .write_encrypted_authenticated(msg)
            .await
            .map_err(|_| todo!())
    }
}
