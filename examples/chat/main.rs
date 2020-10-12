use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::PeerTable;
use aw_rs::conn_manager::{self, ConnectionManager};
use parity_crypto::publickey::{Generator, Public, Random};
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::net;

#[tokio::main]
async fn main() {
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

    // Own keypair.
    let keypair = Random.generate();

    let max_connections = 10;
    let pool = ConnectionPool::new_with_max_connections_allocated(max_connections);
    let table = PeerTable::new();
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));

    tokio::spawn(conn_manager::listen_for_peers(
        conn_manager.clone(),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        addr.port(),
        keypair.clone(),
    ));

    let mut conn =
        conn_manager::get_connection_or_establish(&keypair, &peer_pubkey, addr, &conn_manager)
            .await
            .expect("obtaining connection");
    conn.write(&[1, 2, 3, 4])
        .await
        .expect("writing to connection");
}

fn lower_hex_char_to_nibble(c: char) -> Option<u8> {
    if !c.is_ascii_hexdigit() || c.is_uppercase() {
        return None;
    }
    Some(c as u8 - b'0')
}
