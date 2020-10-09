use aw_rs::handshake;
use futures::executor;
use parity_crypto::publickey::{Generator, Random};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn main() {
    let server_keypair = Random.generate();
    let mut stream = {
        let mut listener = executor::block_on(TcpListener::bind("0.0.0.0:12345")).unwrap();
        executor::block_on(listener.accept()).unwrap().0
    };
    executor::block_on(stream.write_all(server_keypair.public().as_bytes()))
        .expect("initial write");

    let res = executor::block_on(handshake::server_handshake(stream, &server_keypair));
    assert!(res.is_ok());
    let (session_key, client_pubkey) = res.unwrap();
    println!("client pubkey = {:x?}", client_pubkey.as_bytes());
    println!("session key: {:?}", session_key);
}
