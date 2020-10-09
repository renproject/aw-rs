use aw_rs::connection::{Connection, ConnectionPool};
use aw_rs::peer_table::{self, PeerID, PeerTable, PeerTableHandle};
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::env;
use std::net::SocketAddr;
use tokio::net::{self, TcpStream};

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
        Err(e) => {
            // TODO
            return;
        }
    };

    // Own keypair.
    let keypair = Random.generate();

    let conn = connect_with_retry(&keypair, &peer_pubkey, addr);
}

async fn connect_with_retry<'a>(
    keypair: &KeyPair,
    peer_pubkey: &Public,
    addr: SocketAddr,
    peer_table: PeerTableHandle,
    pool: &'a mut ConnectionPool,
) -> Result<&'a mut Connection, ()> {
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        {
            let maybe_conn = get_peer_connection_mut(
                &peer_table::id_from_pubkey(peer_pubkey),
                &peer_table,
                pool,
            );
            match maybe_conn {
                Some(conn) => return Ok(conn),
                _ => (),
            }
            drop(maybe_conn);
        }
        match net::TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let key = aw_rs::handshake::client_handshake(&mut stream, keypair, peer_pubkey)
                    .await
                    .map_err(|_| ())?;
                let conn = Connection::new(stream, &key);
                pool.add_connection(conn);
                let conn = pool.get_conn_mut(&addr).expect("");
                return Ok(conn);
            }
            Err(e) => {
                tokio::time::delay_for(backoff).await;
                backoff = backoff.mul_f32(1.6);
            }
        }
    }
}

fn get_peer_connection_mut<'a>(
    id: &PeerID,
    peer_table: &PeerTableHandle,
    pool: &'a mut ConnectionPool,
) -> Option<&'a mut Connection> {
    let maybe_addr = {
        let peer_table = match peer_table.lock() {
            Ok(table) => table,
            Err(e) => e.into_inner(),
        };
        peer_table.peer_addr(id).cloned()
    };
    if let Some(addr) = maybe_addr {
        if let Some(conn) = pool.get_conn_mut(&addr) {
            Some(conn)
        } else {
            None
        }
    } else {
        None
    }
}

async fn send_to_peer(
    id: &PeerID,
    msg: &[u8],
    peer_table: PeerTableHandle,
    pool: &mut ConnectionPool,
) -> Result<(), ()> {
    let maybe_addr = {
        let peer_table = match peer_table.lock() {
            Ok(table) => table,
            Err(e) => e.into_inner(),
        };
        peer_table.peer_addr(id).cloned()
    };
    if let Some(addr) = maybe_addr {
        if let Some(conn) = pool.get_conn_mut(&addr) {
            conn.write_encrypted_authenticated(msg)
                .await
                .map_err(|_| ())?;
        } else {
            // TODO(ross): There is no live connection for the peer; do we try to establish one
            // now?
            todo!()
        }
    } else {
        // TODO(ross): Peer is not in peer table; do we go and try to query other peers to get the
        // information we need now?
        todo!()
    }
    unimplemented!()
}

fn lower_hex_char_to_nibble(c: char) -> Option<u8> {
    if !c.is_ascii_hexdigit() || c.is_uppercase() {
        return None;
    }
    Some(c as u8 - b'0')
}
