use aw_rs::handshake;
use futures::executor;
use parity_crypto::publickey::{Generator, Public, Random};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

fn main() {
    let external_address = "192.168.15.21:12345";

    let client_keypair = Random.generate();
    println!("client pubkey = {:x?}", client_keypair.public().as_bytes());
    let mut stream = executor::block_on(TcpStream::connect(external_address)).unwrap();
    let mut buf = [0u8; 64];

    executor::block_on(stream.read_exact(&mut buf)).expect("initial read");
    let server_pubkey = Public::from_slice(&buf);

    let res = executor::block_on(handshake::client_handshake(
        stream,
        &client_keypair,
        &server_pubkey,
    ));
    assert!(res.is_ok());
    let session_key = res.unwrap();
    println!("session key: {:?}", session_key);
}
