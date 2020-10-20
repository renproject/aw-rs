use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::PeerTable;
use aw_rs::conn_manager::{self, ConnectionManager};
use aw_rs::util::SharedPtr;
use parity_crypto::publickey;
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::env;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        eprintln!("too many arguments: expected 1, got {:?}", args.len() - 1);
        return;
    }
    let addr_str = args.pop().expect("address arg");
    let port = addr_str.parse().expect("invalid port argument");

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
        port,
    ));

    let cm = conn_manager.clone();
    tokio::task::spawn_blocking(|| read_input(cm, keypair));

    while let Some((sender, msg_res)) = reads.recv().await {
        let pubkey_addr = publickey::public_to_address(&sender);
        match msg_res {
            Ok(msg) => println!("{}: {}", pubkey_addr, std::str::from_utf8(&msg).unwrap()),
            Err(e) => print!("{} error: {:?}", pubkey_addr, e),
        }
    }

    listen_handle.await.unwrap().unwrap();
}

fn read_input(conn_manager: SharedPtr<ConnectionManager>, keypair: KeyPair) {
    let stdin = std::io::stdin();
    let lock = stdin.lock();
    for line in lock.lines() {
        let line = line.expect("TODO");
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
        let conn_manager = conn_manager.clone();
        let msg = input[1..].as_bytes().to_owned();
        tokio::spawn(async move {
            conn_manager::send_to_all(&conn_manager, &msg)
                .await
                .expect("TODO")
        });
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
            conn_manager_lock.add_peer(pubkey, addr);
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
            conn_manager::establish_connection(conn_manager, keypair, &pubkey, addr)
                .await
                .map_err(|_| CommandFailed)?;
            Ok(())
        }
        _ => Err(InvalidCommand),
    }
}
