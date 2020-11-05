use futures::{Future, FutureExt};
use parity_crypto::publickey::{KeyPair, Public};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub mod conn_manager;
pub mod gossip;
pub mod handshake;
pub mod message;
pub mod util;

use conn_manager::{connection::ConnectionPool, peer_table::PeerTable};
use gossip::Decider;
use message::{Header, To};

pub use conn_manager::peer_table::id_from_pubkey;

pub type ConnectionManager = conn_manager::ConnectionManager<Decider>;

#[derive(Debug)]
pub enum Error {
    Gossip(mpsc::error::TrySendError<(Public, Vec<u8>)>),
    Listen(conn_manager::Error),
    Internal,
}

pub fn new_aw_task<F>(
    own_keypair: KeyPair,
    port: u16,
    will_pull: F,
    max_connections: usize,
    max_header_len: usize,
    max_data_len: usize,
    buffer_size: usize,
    alpha: usize,
) -> (
    impl Future<Output = Result<(), Error>>,
    Arc<Mutex<ConnectionManager>>,
    mpsc::Sender<(To, Vec<u8>, Vec<u8>)>,
    mpsc::Receiver<(Public, Vec<u8>)>,
)
where
    F: Fn(&Header) -> bool + Send + Sync + 'static,
{
    let own_pubkey = *own_keypair.public();
    let decider = Decider::new();
    let (pool, mut reads) = ConnectionPool::new_with_max_connections_allocated(
        max_connections,
        max_header_len,
        max_data_len,
        buffer_size,
        decider.clone(),
    );
    let table = PeerTable::new();
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));
    let (gossip_fut, mut cm_in, gossip_in, gossip_out) = gossip::gossip_task(
        buffer_size,
        alpha,
        own_pubkey,
        will_pull,
        &decider,
        conn_manager.clone(),
    );
    let gossip_fut = gossip_fut.map(|res| res.map_err(Error::Gossip));
    let cm_to_gossiper_fut = async move {
        while let Some(msg) = reads.recv().await {
            if cm_in.send(msg).await.is_err() {
                break;
            }
        }
        Result::<(), ()>::Err(())
    }
    .map(|res| res.map_err(|_| Error::Internal));

    let listen_fut = conn_manager::listen_for_peers(
        conn_manager.clone(),
        own_keypair.clone(),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        port,
    )
    .map(|res| res.map_err(Error::Listen));
    let task = futures::future::try_join3(gossip_fut, cm_to_gossiper_fut, listen_fut)
        .map(|res| res.map(drop));

    (task, conn_manager, gossip_in, gossip_out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn gossip_in_partially_connected_network() {}
}
