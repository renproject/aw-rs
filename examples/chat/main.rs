use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::PeerTable;
use aw_rs::conn_manager::{self, ConnectionManager};
use aw_rs::util::SharedPtr;
use parity_crypto::publickey;
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::io::BufRead;
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

    // let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    let keypair = Random.generate();
    println!("own pubkey: {:x?}", keypair.public());
    println!("own address: {:?}", keypair.address());

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

    let cm = conn_manager.clone();
    tokio::task::spawn_blocking(|| read_input(cm, keypair));

    while let Some((sender, msg)) = reads.recv().await {
        println!(
            "{}: {}",
            publickey::public_to_address(&sender),
            std::str::from_utf8(&msg).unwrap()
        );
    }

    listen_handle.await.unwrap().unwrap();
}

fn read_input(conn_manager: SharedPtr<ConnectionManager>, keypair: KeyPair) {
    let stdin = std::io::stdin();
    let lock = stdin.lock();
    for line in lock.lines() {
        let line = line.expect("TODO");
        println!("parsing: {:?}", line);
        if let Err(e) = parse_input(&conn_manager, &keypair, &line) {
            eprintln!("{:?}", e);
        }
    }
}

#[derive(Debug)]
enum ParseError {
    CommandFailed,
    InvalidCommand,
    InvalidInput,
    InvalidArguments,
}

fn parse_input(
    conn_manager: &SharedPtr<ConnectionManager>,
    keypair: &KeyPair,
    input: &str,
) -> Result<(), ParseError> {
    if input.starts_with("/") && !input.starts_with("//") {
        return futures::executor::block_on(parse_command(
            conn_manager,
            keypair,
            input.strip_prefix("/").unwrap(),
        ));
    }

    if input.starts_with("@") {
        // TODO(ross): Direct message.
    }

    if input.starts_with("#") {
        // TODO(ross): Subnet message.
    }

    if input.starts_with("*") {
        let mut conn_manager_lock = match conn_manager.lock() {
            Ok(lock) => lock,
            Err(e) => e.into_inner(),
        };
        conn_manager_lock
            .send_to_all(&input[1..].as_bytes())
            .expect("TODO");
        return Ok(());
    }

    Err(ParseError::InvalidInput)
}

async fn parse_command(
    conn_manager: &SharedPtr<ConnectionManager>,
    keypair: &KeyPair,
    command: &str,
) -> Result<(), ParseError> {
    use ParseError::*;

    let mut words = command.split_ascii_whitespace();
    let command = words.next().ok_or(InvalidCommand)?;

    match command {
        "add" => {
            println!("adding peer...");
            let mut conn_manager_lock = match conn_manager.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let pubkey = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| Public::from_str(s).map_err(|_| InvalidArguments))?;
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager_lock.add_peer(&pubkey, addr);
            Ok(())
        }
        "connect" => {
            let pubkey = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| Public::from_str(s).map_err(|_| InvalidArguments))?;
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager::get_connection_or_establish(conn_manager, keypair, &pubkey, addr)
                .await
                .map_err(|_| CommandFailed)?;
            Ok(())
        }
        _ => Err(InvalidCommand),
    }
}

/*
fn lower_hex_char_to_nibble(c: char) -> Option<u8> {
    if !c.is_ascii_hexdigit() || c.is_uppercase() {
        return None;
    }
    Some(c as u8 - b'0')
}
*/
