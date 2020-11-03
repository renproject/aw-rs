use aw::handshake;
use futures::executor;
use parity_crypto::publickey::{Generator, Random};
use tokio::net::TcpStream;

fn main() {
    let external_address = "192.168.15.21:12345";

    let client_keypair = Random.generate();
    println!("client pubkey = {:x?}", client_keypair.public().as_bytes());
    let stream = executor::block_on(TcpStream::connect(external_address)).unwrap();

    let res = executor::block_on(handshake::client_handshake(stream, &client_keypair, None));
    assert!(res.is_ok());
    let (session_key, server_pubkey) = res.unwrap();
    println!("server pubkey: {:x?}", server_pubkey);
    println!("session key: {:?}", session_key);
}
