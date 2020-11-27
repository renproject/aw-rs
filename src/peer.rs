use crate::conn_manager::{
    self, connection::SynDecider, peer_table::SignedAddress, ConnectionManager,
};
use crate::message::{Header, Message, Variant, UNUSED_PEER_ID, V1};
use futures::Future;
use parity_crypto::publickey::{KeyPair, Public};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

// TODO(ross): This module will need to be updated when we add logic for filtering based on the
// public key of a peer. For example, when handling a ping response we should check to see if the
// recovered public key matches the filter predicate and act accordingly.

pub struct Options {
    pub pinger_options: PingerOptions,
    pub peer_alpha: usize,
    pub buffer_size: usize,
}

pub struct PingerOptions {
    pub ping_interval: Duration,
    pub ping_alpha: usize,
    pub ping_ttl: Duration,
    pub send_backoff: Duration,
    pub send_backoff_multiplier: f64,
}

pub enum Error {}

pub fn peer_discovery_task<T: SynDecider + Clone + Send + 'static>(
    conn_manager: Arc<Mutex<ConnectionManager<T>>>,
    keypair: KeyPair,
    own_addr: Option<SignedAddress>,
    options: Options,
) -> (
    impl Future<Output = ()>,
    impl Future<Output = ()>,
    mpsc::Sender<(Public, Message)>,
) {
    let Options {
        pinger_options,
        peer_alpha,
        buffer_size,
    } = options;

    let own_pubkey = *keypair.public();
    let (sender, receiver) = mpsc::channel(buffer_size);
    let ping_sender_fut = ping_sender(conn_manager.clone(), keypair, own_addr, pinger_options);
    let ping_handler_fut = ping_handler(conn_manager, own_pubkey, receiver, peer_alpha);

    (ping_sender_fut, ping_handler_fut, sender)
}

async fn ping_sender<T: SynDecider + Clone + Send + 'static>(
    conn_manager: Arc<Mutex<ConnectionManager<T>>>,
    keypair: KeyPair,
    own_addr: Option<SignedAddress>,
    options: PingerOptions,
) {
    let PingerOptions {
        ping_interval,
        ping_alpha,
        ping_ttl,
        send_backoff,
        send_backoff_multiplier,
    } = options;

    let mut ping_timer = time::interval(ping_interval);
    loop {
        ping_timer.tick().await;

        let ping = Message::Header(Header::new(
            V1,
            Variant::Ping,
            UNUSED_PEER_ID,
            ping_data(own_addr.clone()),
        ));
        let peers = {
            let conn_manager = conn_manager.lock().unwrap();
            conn_manager.random_peer_subset(ping_alpha)
        };
        futures::future::join_all(peers.iter().map(|peer| {
            conn_manager::send_with_establish(
                &conn_manager,
                &keypair,
                &peer,
                ping.clone(),
                Some(ping_ttl),
                send_backoff,
                send_backoff_multiplier,
            )
        }))
        .await;
    }
}

async fn ping_handler<T: SynDecider + Clone + Send + 'static>(
    conn_manager: Arc<Mutex<ConnectionManager<T>>>,
    own_pubkey: Public,
    mut receiver: mpsc::Receiver<(Public, Message)>,
    peer_alpha: usize,
) {
    while let Some((pubkey, msg)) = receiver.recv().await {
        if let Message::Header(header) = msg {
            match header.variant {
                Variant::Ping => {
                    // If there was a signed address included, check it and add if it is ok then
                    // add it to our own peer table.
                    if header.data.len() != 0 {
                        if let Ok(addr) = SignedAddress::try_from(header.data) {
                            if let Ok(signatory) = addr.signatory() {
                                if signatory == pubkey {
                                    let mut conn_manager = conn_manager.lock().unwrap();
                                    let _existing = conn_manager.add_signed_peer(pubkey, addr);
                                }
                            }
                        }
                    }

                    if let Some(response) = response(&conn_manager, peer_alpha) {
                        let pong = Message::Header(Header::new(
                            V1,
                            Variant::Pong,
                            UNUSED_PEER_ID,
                            response,
                        ));

                        // TODO(ross): I think we don't care if we don't successfully send the pong
                        // (especially in the case that the connection was dropped), but we should
                        // confirm this.
                        conn_manager::try_send_peer(&conn_manager, &pubkey, pong)
                            .await
                            .ok();
                    }
                }
                Variant::Pong => {
                    let mut signed_addrs = Vec::new();
                    let mut bytes = header.data.as_slice();
                    loop {
                        match SignedAddress::from_bytes_with_tail(bytes) {
                            Ok((signed_addr, rest)) => {
                                signed_addrs.push(signed_addr);
                                bytes = rest;
                                if bytes.len() == 0 {
                                    break;
                                }
                            }
                            Err(_e) => {
                                // TODO(ross): Terminate the connection/update relevant reputation
                                // or similar.
                                todo!()
                            }
                        }
                    }
                    handle_ping_response(&conn_manager, signed_addrs, &own_pubkey);
                }
                _ => {
                    // TODO(ross): Create a further subdivision of types/enums so that we do not
                    // have to consider this case.
                    unreachable!()
                }
            }
        }
    }
}

fn ping_data(own_addr: Option<SignedAddress>) -> Vec<u8> {
    own_addr.map(Vec::<u8>::from).unwrap_or(Vec::new())
}

fn response<T>(
    conn_manager: &Arc<Mutex<ConnectionManager<T>>>,
    peer_count: usize,
) -> Option<Vec<u8>> {
    // TODO(ross): We need to decide what to do when locking a mutex. Currently in most of the rest
    // of the crate we take the guard even when the mutex has been poisoned, but it is likely that
    // we don't actually want to do this. The mutex is only poisoned when a thread holding a lock
    // panics, and it is probably that case that the code that is executing when a lock is being
    // held will not panic. In this case, unwrapping is the correct choice. However, we would need
    // to make sure that this non-panicking property is held every time we take a lock.
    let conn_manager = conn_manager.lock().unwrap();
    let peers = conn_manager.random_signed_address_subset(peer_count);
    if peers.len() == 0 {
        None
    } else {
        Some(peers.into_iter().map(Vec::<u8>::from).flatten().collect())
    }
}

fn handle_ping_response<T>(
    conn_manager: &Arc<Mutex<ConnectionManager<T>>>,
    peers: Vec<SignedAddress>,
    own_pubkey: &Public,
) {
    let mut conn_manager = conn_manager.lock().unwrap();
    for peer in peers {
        // NOTE(ross): Here we ignore any addresses that don't have a valid associated public key.
        // However, when we want to use the fact that the address was not valid to, for example,
        // modify the reputation or similar of a peer, we should do so in the Err branch here.
        if let Ok(signatory) = peer.signatory() {
            if &signatory != own_pubkey {
                // TODO(ross): What will we do when there this peer was already in the peer table?
                let _existing = conn_manager.add_signed_peer(signatory, peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn_manager::{
        self, connection::ConnectionPool, peer_table::PeerTable, ConnectionManager,
    };
    use crate::gossip::Decider;
    use futures::FutureExt;
    use parity_crypto::publickey::{Generator, KeyPair, Random};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_peer() -> (
        KeyPair,
        u16,
        Arc<Mutex<ConnectionManager<Decider>>>,
        impl Future<Output = ()>,
    ) {
        let max_connections = 100;
        let max_header_len = 1024;
        let max_data_len = 1024;

        let pinger_options = PingerOptions {
            ping_interval: Duration::from_millis(10),
            ping_alpha: 3,
            ping_ttl: Duration::from_secs(10),
            send_backoff: Duration::from_millis(1),
            send_backoff_multiplier: 1.6,
        };
        let options = Options {
            pinger_options,
            peer_alpha: 3,
            buffer_size: 100,
        };

        let keypair = Random.generate();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let decider = Decider::new();
        let (pool, mut pool_receiver) = ConnectionPool::new_with_max_connections_allocated(
            max_connections,
            max_header_len,
            max_data_len,
            options.buffer_size,
            decider,
        );
        let table = PeerTable::new();
        let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));
        let (port, listen_fut) =
            conn_manager::listen_for_peers(conn_manager.clone(), keypair.clone(), addr, 0).unwrap();
        let signed_addr =
            SignedAddress::new(SocketAddr::new(addr, port), keypair.secret()).unwrap();

        let (pinger_task, handler_task, mut ping_pong_sender) = peer_discovery_task(
            conn_manager.clone(),
            keypair.clone(),
            Some(signed_addr),
            options,
        );

        let cm_to_pinger_fut = async move {
            while let Some(msg) = pool_receiver.recv().await {
                if ping_pong_sender.send(msg).await.is_err() {
                    break;
                }
            }
        };

        let fut = futures::future::join4(listen_fut, pinger_task, handler_task, cm_to_pinger_fut);
        (keypair, port, conn_manager, fut.map(drop))
    }

    #[tokio::test]
    async fn peer_discovery() {
        let n = 6;

        let mut keypairs = Vec::with_capacity(n);
        let mut ports = Vec::with_capacity(n);
        let mut futures = Vec::with_capacity(n);
        let mut connection_managers = Vec::with_capacity(n);
        for _ in 0..n {
            let (keypair, port, connection_manager, future) = create_peer();
            keypairs.push(keypair);
            ports.push(port);
            futures.push(future);
            connection_managers.push(connection_manager);
        }

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

        let mut timer = time::interval(Duration::from_millis(2));
        let mut count = 0;
        let check_fut = async move {
            'outer: loop {
                timer.tick().await;
                count += 1;
                for connection_manager in connection_managers.iter() {
                    let connection_manager = connection_manager.lock().unwrap();
                    if connection_manager.num_peers() != n - 1 {
                        continue 'outer;
                    }
                }
                println!("finished after {} checks", count);
                break;
            }
        };
        check_fut.await;
    }
}
