use futures::{Future, FutureExt};
use parity_crypto::publickey::{KeyPair, Public};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// TOOD(ross): It is likely that not all of these will be made public, but others should be public
// only to this crate.
pub mod conn_manager;
pub mod gossip;
pub mod handshake;
pub mod message;
pub mod peer;
pub mod rate;
pub mod util;

use conn_manager::{
    connection::{self, ConnectionPool},
    peer_table::{PeerTable, SignedAddress},
};
use gossip::Decider;
use message::{Header, Message, To};

pub use conn_manager::peer_table::id_from_pubkey;

pub type ConnectionManager = conn_manager::ConnectionManager<Decider>;

#[derive(Debug)]
pub enum Error {
    Gossip(mpsc::error::TrySendError<(Public, Vec<u8>)>),
    Listen(io::Error),
    Internal,
}

pub fn new_aw_task<F>(
    own_keypair: KeyPair,
    own_addr: Option<SignedAddress>,
    will_pull: F,
    gossip_options: gossip::Options,
    peer_options: peer::Options,
    listener_rate_limiter_options: rate::MapOptions,
    port: u16,
    pool_options: connection::Options,
) -> Result<
    (
        impl Future<Output = Result<(), Error>>,
        Arc<Mutex<ConnectionManager>>,
        u16,
        mpsc::Sender<(To, Vec<u8>, Vec<u8>)>,
        mpsc::Receiver<(Public, Vec<u8>)>,
    ),
    io::Error,
>
where
    F: Fn(&Header) -> bool + Send + Sync + 'static,
{
    let decider = Decider::new();
    let (pool, mut reads) =
        ConnectionPool::new_with_max_connections_allocated(pool_options, decider.clone());
    let table = PeerTable::new();
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));
    let (gossip_fut, mut gossip_network_in, gossip_in, gossip_out) = gossip::gossip_task(
        own_keypair.clone(),
        conn_manager.clone(),
        &decider,
        will_pull,
        gossip_options,
    );
    let (ping_sender_fut, ping_handler_fut, mut peer_network_in) = peer::peer_discovery_task(
        conn_manager.clone(),
        own_keypair.clone(),
        own_addr,
        peer_options,
    );
    let ping_sender_fut = ping_sender_fut.map(Result::<(), Error>::Ok);
    let ping_handler_fut = ping_handler_fut.map(Result::<(), Error>::Ok);
    let gossip_fut = gossip_fut.map(|res| res.map_err(Error::Gossip));
    let route_incoming_fut = async move {
        while let Some(msg) = reads.recv().await {
            match &msg {
                (_, Message::Header(header)) if header.variant.is_peer_message() => {
                    if peer_network_in.send(msg).await.is_err() {
                        break;
                    }
                }
                _ => {
                    if gossip_network_in.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
        Result::<(), _>::Err(Error::Internal)
    };

    let (port, listen_fut) = conn_manager::listen_for_peers(
        conn_manager.clone(),
        own_keypair.clone(),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        port,
        listener_rate_limiter_options,
    )?;
    let listen_fut = listen_fut.map(Result::<(), Error>::Ok);
    let task = futures::future::try_join5(
        gossip_fut,
        ping_sender_fut,
        ping_handler_fut,
        route_incoming_fut,
        listen_fut,
    )
    .map(|res| res.map(drop));

    Ok((task, conn_manager, port, gossip_in, gossip_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::conn_manager::peer_table;
    use crate::message::GOSSIP_PEER_ID;
    use parity_crypto::publickey::{Generator, Random};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[tokio::test]
    async fn gossip_in_partially_connected_network() {
        // Numer of peers.
        let n = 10;

        let own_addr = None;
        let pool_options = connection::Options::default();
        let gossip_options = gossip::Options::default();
        let peer_options = peer::Options::default();
        let listener_rate_limiter_options = rate::MapOptions {
            capacity: 1000,
            limit: 10,
            period: Duration::from_secs(60),
        };

        let keypairs: Vec<_> = (0..n).map(|_| Random.generate()).collect();

        let mut futures = Vec::with_capacity(n);
        let mut connection_managers = Vec::with_capacity(n);
        let mut ports = Vec::with_capacity(n);
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for keypair in keypairs.iter() {
            let public = *keypair.public();
            let will_pull = move |header: &Header| {
                header.to == peer_table::id_from_pubkey(&public) || header.to == GOSSIP_PEER_ID
            };
            let (future, connection_manager, port, sender, receiver) = new_aw_task(
                keypair.clone(),
                own_addr.clone(),
                will_pull,
                gossip_options.clone(),
                peer_options.clone(),
                listener_rate_limiter_options.clone(),
                0,
                pool_options,
            )
            .expect("creaing aw task");

            futures.push(future);
            connection_managers.push(connection_manager);
            ports.push(port);
            senders.push(sender);
            receivers.push(receiver);
        }

        // let _aw_handle = tokio::spawn(futures::future::try_join_all(futures.into_iter()));
        for future in futures {
            tokio::spawn(future);
        }

        // Line topology.
        futures::future::try_join_all((0..n - 1).map(|i| {
            conn_manager::establish_connection(
                &connection_managers[i],
                &keypairs[i],
                keypairs[i + 1].public(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), ports[i + 1]),
                None,
            )
        }))
        .await
        .expect("connections");

        for sender in 0..n {
            let message: [u8; 32] = rand::random();
            let send_res =
                senders[sender].try_send((To::Gossip, message.to_vec(), message.to_vec()));
            assert!(send_res.is_ok());

            let recvs = (0..n).filter(|i| i != &sender);
            for receiver in recvs {
                let (from, received_message) = receivers[receiver].recv().await.expect("receiving");
                assert_eq!(received_message, message.to_vec());
                match receiver {
                    0 => assert_eq!(&from, keypairs[1].public()),
                    r if 0 < r && r <= n - 1 => assert!(
                        &from == keypairs[receiver - 1].public()
                            || &from == keypairs[receiver + 1].public()
                    ),
                    r if r == n - 1 => assert_eq!(&from, keypairs[n - 2].public()),
                    _ => unreachable!(),
                }
            }
        }
    }
}
