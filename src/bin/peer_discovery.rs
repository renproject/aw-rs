use aw::conn_manager::{
    self,
    connection::ConnectionPool,
    peer_table::{PeerTable, SignedAddress},
    ConnectionManager,
};
use aw::gossip::Decider;
use aw::peer::{self, Options, PingerOptions};
use futures::Future;
use futures::FutureExt;
use parity_crypto::publickey::{Generator, KeyPair, Random};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;

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
    let signed_addr = SignedAddress::new(SocketAddr::new(addr, port), keypair.secret()).unwrap();

    let (pinger_task, handler_task, mut ping_pong_sender) = peer::peer_discovery_task(
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

#[tokio::main(core_threads = 1)]
async fn main() {
    let n = 5;

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

    let now = Instant::now();

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

    println!("finished in {}ms", now.elapsed().as_millis());
}
