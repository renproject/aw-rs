use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::PeerTable;
use aw_rs::conn_manager::{self, ConnectionManager};
use parity_crypto::publickey::{Generator, Public, Random};
// use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
// use tokio::net;

#[tokio::main]
async fn main() {
    /*
    let mut args: Vec<String> = env::args().collect();
    if args.len() > 3 {
        eprintln!("too many arguments: expected 2, got {:?}", args.len() - 1);
        return;
    }
    let addr_str = args.pop().expect("address arg");
    let pubkey_str = args.pop().expect("pubkey arg");

    // Parse peer ID.
    if pubkey_str.len() != 128 {
        // TODO
        return;
    }
    let mut pubkey_bytes = [0u8; 64];
    for i in 0..32 {
        let lower = lower_hex_char_to_nibble(pubkey_str.bytes().nth(2 * i).unwrap() as char);
        let upper = lower_hex_char_to_nibble(pubkey_str.bytes().nth(2 * i + 1).unwrap() as char);
        match (lower, upper) {
            (Some(lower), Some(upper)) => pubkey_bytes[i] = lower + (upper << 4),
            _ => {
                // TODO
                return;
            }
        }
    }
    let peer_pubkey = Public::from_slice(&pubkey_bytes);

    // Parse peer address.
    let addr = match net::lookup_host(addr_str).await {
        Ok(mut iter) => {
            match iter.next() {
                Some(addr) => addr,
                None => {
                    // TODO
                    return;
                }
            }
        }
        Err(_e) => {
            // TODO
            return;
        }
    };
    */

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    let keypair = Random.generate();
    println!("own keypair: {:x?}", keypair.public());

    // let peer = None;
    let peer = Some(Public::from_str("fa85cc71a2d291574b5f9ff424018229969ee3aceff8a88fc514c490be7ef7898023e411b966b14e618f53e4dc8223ae873e60938f0ab420208d608a64f07633").unwrap());

    let max_connections = 10;
    let (pool, mut reads) = ConnectionPool::new_with_max_connections_allocated(max_connections);
    let table = PeerTable::new();
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));

    let listen_handle = tokio::spawn(conn_manager::listen_for_peers(
        conn_manager.clone(),
        keypair.clone(),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        12346,
    ));

    if let Some(peer) = peer {
        let mut conn =
            conn_manager::get_connection_or_establish(&conn_manager, &keypair, &peer, addr)
                .await
                .expect("obtaining connection");
        conn.write(&[1, 2, 3, 4])
            .await
            .expect("writing to connection");
    } else {
        while let Some((sender, msg)) = reads.recv().await {
            println!("{:?}: {:?}", sender, msg);
        }
    }

    listen_handle.await.unwrap().unwrap();
}

/*
fn lower_hex_char_to_nibble(c: char) -> Option<u8> {
    if !c.is_ascii_hexdigit() || c.is_uppercase() {
        return None;
    }
    Some(c as u8 - b'0')
}
*/
