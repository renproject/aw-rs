use aw::conn_manager::{self, peer_table};
use aw::message::{Header, To, GOSSIP_PEER_ID};
use parity_crypto::publickey::{Generator, Random};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

#[tokio::main(core_threads = 2)]
async fn main() {
    // Numer of peers.
    let n = 10;

    let max_connections = 10;
    let max_header_len = 1024;
    let max_data_len = 1024;
    let buffer_size = 100;
    let alpha = 3;

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
        let (future, connection_manager, port, sender, receiver) = aw::new_aw_task(
            keypair.clone(),
            0,
            will_pull,
            max_connections,
            max_header_len,
            max_data_len,
            buffer_size,
            alpha,
        )
        .expect("creaing aw task");

        futures.push(future);
        connection_managers.push(connection_manager);
        ports.push(port);
        senders.push(sender);
        receivers.push(receiver);
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
        )
    }))
    .await
    .expect("connections");

    let now = Instant::now();
    for sender in 0..n {
        let message: [u8; 32] = rand::random();
        let send_res = senders[sender].try_send((To::Gossip, message.to_vec(), message.to_vec()));
        assert!(send_res.is_ok());

        // let recvs = (0..n).filter(|i| i != &sender);
        let recvs = (0..sender).rev().chain((sender + 1)..n);
        println!("{:?}", recvs.collect::<Vec<_>>());
        let recvs = (0..sender).rev().chain((sender + 1)..n);
        for receiver in recvs {
            let (from, received_message) = receivers[receiver].recv().await.expect("receiving");
            assert_eq!(received_message, message.to_vec());
            if receiver == 0 {
                assert_eq!(&from, keypairs[1].public());
            } else if 0 < receiver && receiver <= n - 1 {
                assert!(
                    &from == keypairs[receiver - 1].public()
                        || &from == keypairs[receiver + 1].public()
                );
            } else if receiver == n - 1 {
                assert_eq!(&from, keypairs[n - 2].public());
            } else {
                unreachable!()
            }
        }
    }

    println!("gossiping completed in: {}ms", now.elapsed().as_millis());
}
