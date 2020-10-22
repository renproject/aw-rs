use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::PeerTable;
use aw_rs::conn_manager::{self, ConnectionManager};
use aw_rs::util::SharedPtr;
use parity_crypto::publickey;
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::collections::HashMap;
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

    let aliases = Arc::new(Mutex::new(Aliases::new()));
    let aliases_clone = aliases.clone();
    let cm = conn_manager.clone();
    tokio::task::spawn_blocking(|| read_input(cm, aliases_clone, keypair));

    while let Some((sender, msg_res)) = reads.recv().await {
        let pubkey_addr = publickey::public_to_address(&sender);
        let aliases = aw_rs::util::get_lock(&aliases);
        match (msg_res, aliases.get_by_pubkey(&sender)) {
            (Ok(msg), Some(name)) => println!("{}: {}", name, std::str::from_utf8(&msg).unwrap()),
            (Ok(msg), None) => println!("{}: {}", pubkey_addr, std::str::from_utf8(&msg).unwrap()),
            (Err(e), Some(name)) => print!("{} error: {:?}", name, e),
            (Err(e), None) => print!("{} error: {:?}", pubkey_addr, e),
        }
    }

    listen_handle.await.unwrap().unwrap();
}

fn read_input(
    conn_manager: SharedPtr<ConnectionManager>,
    mut aliases: SharedPtr<Aliases>,
    keypair: KeyPair,
) {
    let stdin = std::io::stdin();
    let lock = stdin.lock();
    for line in lock.lines() {
        let line = line.expect("TODO");
        if let Err(e) = parse_input(&conn_manager, &mut aliases, &keypair, &line) {
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
    aliases: &mut SharedPtr<Aliases>,
    keypair: &KeyPair,
    input: &str,
) -> Result<(), ParseError> {
    if input.starts_with("/") && !input.starts_with("//") {
        return futures::executor::block_on(parse_command(
            conn_manager,
            aliases,
            keypair,
            input.strip_prefix("/").unwrap(),
        ));
    }

    if input.starts_with("@") {
        let conn_manager = conn_manager.clone();
        let (peer, msg) = {
            let trimmed = &input[1..];
            let aliases = aw_rs::util::get_lock(aliases);
            let i = trimmed.find(" ").ok_or(ParseError::InvalidInput)?;
            let (peer, msg) = (&trimmed[..i], &trimmed[i + 1..]);
            (
                aliases.pubkey_from_maybe_alias(peer)?,
                msg.as_bytes().to_owned(),
            )
        };
        tokio::spawn(async move {
            if let Err(e) = conn_manager::try_send_peer(&conn_manager, &peer, &msg).await {
                println!(
                    "could not reach peer {}: {:?}",
                    publickey::public_to_address(&peer),
                    e
                );
            }
        });
        return Ok(());
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
    aliases: &mut SharedPtr<Aliases>,
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
            let pubkey = {
                let aliases = aw_rs::util::get_lock(aliases);
                let pubkey = words.next().ok_or(InvalidArguments)?;
                aliases.pubkey_from_maybe_alias(pubkey)?
            };
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager_lock.add_peer(pubkey, addr);
            Ok(())
        }
        "connect" => {
            let pubkey = {
                let aliases = aw_rs::util::get_lock(aliases);
                let pubkey = words.next().ok_or(InvalidArguments)?;
                aliases.pubkey_from_maybe_alias(pubkey)?
            };
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager::establish_connection(conn_manager, keypair, &pubkey, addr)
                .await
                .map_err(|_| CommandFailed)?;
            Ok(())
        }
        "alias" => {
            let pubkey = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| Public::from_str(s).map_err(|_| InvalidArguments))?;
            let name = words.next().ok_or(InvalidArguments).map(str::to_string)?;
            let mut aliases = aw_rs::util::get_lock(aliases);
            let _ = aliases.insert(name, pubkey);
            Ok(())
        }
        _ => Err(InvalidCommand),
    }
}

struct Aliases {
    by_pubkey: HashMap<Public, String>,
    by_name: HashMap<String, Public>,
}

impl Aliases {
    fn new() -> Self {
        let by_pubkey = HashMap::new();
        let by_name = HashMap::new();
        Self { by_pubkey, by_name }
    }

    fn insert(&mut self, name: String, pubkey: Public) {
        let _ = self.by_name.insert(name.clone(), pubkey);
        let _ = self.by_pubkey.insert(pubkey, name);
    }

    fn get_by_name(&self, name: &str) -> Option<&Public> {
        self.by_name.get(name)
    }

    fn get_by_pubkey(&self, pubkey: &Public) -> Option<&String> {
        self.by_pubkey.get(pubkey)
    }

    fn pubkey_from_maybe_alias(&self, name: &str) -> Result<Public, ParseError> {
        match self.get_by_name(name) {
            Some(pubkey) => Ok(pubkey.to_owned()),
            None => Public::from_str(name).map_err(|_| ParseError::InvalidArguments),
        }
    }
}
