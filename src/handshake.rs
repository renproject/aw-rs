use futures::{future, Future};
use parity_crypto::publickey::{self, ecies, KeyPair, Public, Secret};
use secp256k1::group::{fe::Fe, Ge};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot::{self, error::RecvError};

const SECRET_SIZE: usize = 32;
const PUBKEY_SIZE: usize = 64;

// Number of bytes of metadata in an encrypted message. In other words, ENC_META_LEN + (length of
// message) is the number of bytes in a full encrypted message.
//
// NOTE(ross): This was taken from the parity_crypto library. It should in general be derived from
// the specifcation of the symmetric encryption scheme being used in ECIES.
const ENC_META_LEN: usize = 1 + 64 + 16 + 32;

const ENC_SECRET_SIZE: usize = ENC_META_LEN + SECRET_SIZE;

const MAX_CLIENT_READ_SIZE: usize = ENC_SECRET_SIZE;
const MAX_SERVER_READ_SIZE: usize = 2 * SECRET_SIZE + ENC_META_LEN;

#[derive(Debug)]
pub enum Error {
    Write(io::Error),
    Read(io::Error),
    Encryption(publickey::Error),
    Decryption(publickey::Error),
    Sender,
    Receiver,
    EchoMismatch,
    InvalidPubkey,
    PubKeyMismatch,
}

impl From<RecvError> for Error {
    fn from(_: RecvError) -> Self {
        Self::Receiver
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub async fn handshake(
    conn: &mut TcpStream,
    own_keypair: &KeyPair,
    expected_peer_pubkey: Option<&Public>,
) -> Result<([u8; 32], Public)> {
    // NOTE(ross): Using `split` instead of `into_split` here forces us to complete both halves of
    // the handshake in the same task. We will need to use the latter method if we want the
    // handshake to run on separate tasks.
    let (read_half, write_half) = conn.split();
    let (peer_pubkey_sender, peer_pubkey_receiver) = oneshot::channel();
    let (peer_secret_sender, peer_secret_receiver) = oneshot::channel();
    let own_secret = rand::random::<[u8; 32]>();

    let read_fut = handshake_read_half(
        read_half,
        own_keypair,
        expected_peer_pubkey,
        own_secret,
        peer_pubkey_sender,
        peer_secret_sender,
    );
    let write_fut = handshake_write_half(
        write_half,
        own_keypair.public(),
        own_secret,
        peer_pubkey_receiver,
        peer_secret_receiver,
    );

    // NOTE(ross): Here we are joining, so we have only one task and the read and write futures
    // will not be able to execute in parallel. Separate tasks should be used if we desire parallel
    // execution.
    let ((peer_pubkey, peer_secret), _) = future::try_join(read_fut, write_fut).await?;
    let session_key = session_key(&own_secret, &peer_secret);
    Ok((session_key, peer_pubkey))
}

async fn handshake_write_half<W, PKF, SF>(
    mut writer: W,
    own_pubkey: &Public,
    own_secret: [u8; 32],
    peer_pubkey_fut: PKF,
    peer_secret_fut: SF,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    PKF: Future<Output = std::result::Result<Public, RecvError>>,
    SF: Future<Output = std::result::Result<[u8; 32], RecvError>>,
{
    writer
        .write_all(own_pubkey.as_bytes())
        .await
        .map_err(Error::Write)?;
    let peer_pubkey = peer_pubkey_fut.await?;

    let msg_enc = ecies::encrypt(&peer_pubkey, &[], &own_secret).map_err(Error::Encryption)?;
    writer.write_all(&msg_enc).await.map_err(Error::Write)?;

    let peer_secret = peer_secret_fut.await?;
    let msg_enc = ecies::encrypt(&peer_pubkey, &[], &peer_secret).map_err(Error::Encryption)?;
    writer.write_all(&msg_enc).await.map_err(Error::Write)
}

async fn handshake_read_half<R: AsyncRead + Unpin>(
    mut reader: R,
    own_keypair: &KeyPair,
    expected_peer_pubkey: Option<&Public>,
    own_secret: [u8; 32],
    peer_pubkey_sender: oneshot::Sender<Public>,
    peer_secret_sender: oneshot::Sender<[u8; 32]>,
) -> Result<(Public, [u8; 32])> {
    let mut buf = [0u8; MAX_CLIENT_READ_SIZE];

    let read_buf = &mut buf[..PUBKEY_SIZE];
    reader.read_exact(read_buf).await.map_err(Error::Read)?;
    let peer_pubkey = read_pubkey(read_buf)?;
    if let Some(expected_peer_pubkey) = expected_peer_pubkey {
        if &peer_pubkey != expected_peer_pubkey {
            return Err(Error::PubKeyMismatch);
        }
    }
    peer_pubkey_sender
        .send(peer_pubkey)
        .map_err(|_| Error::Sender)?;

    let mut peer_secret = [0u8; 32];
    let read_buf = &mut buf[..ENC_SECRET_SIZE];
    reader.read_exact(read_buf).await.map_err(Error::Read)?;
    peer_secret.copy_from_slice(&client_read_server_secret(read_buf, own_keypair.secret())?);
    peer_secret_sender
        .send(peer_secret)
        .map_err(|_| Error::Sender)?;

    let read_buf = &mut buf[..ENC_SECRET_SIZE];
    reader.read_exact(read_buf).await.map_err(Error::Read)?;
    client_read_and_check_secret_echo(read_buf, own_keypair.secret(), &own_secret)?;

    Ok((peer_pubkey, peer_secret))
}

pub async fn client_handshake<RW: AsyncRead + AsyncWrite + Unpin>(
    mut conn: RW,
    client_keypair: &KeyPair,
    expected_server_pubkey: Option<&Public>,
) -> Result<([u8; 32], Public)> {
    use Error::*;

    let mut buf = [0u8; MAX_CLIENT_READ_SIZE];

    // Read public key.
    let read_buf = &mut buf[..PUBKEY_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    let server_pubkey = read_pubkey(read_buf)?;
    if let Some(expected_server_pubkey) = expected_server_pubkey {
        if &server_pubkey != expected_server_pubkey {
            return Err(PubKeyMismatch);
        }
    }

    // Write public key.
    conn.write_all(client_keypair.public().as_bytes())
        .await
        .map_err(Write)?;

    // Read encrypted server secret.
    let mut secrets = [0u8; 2 * SECRET_SIZE];
    let read_buf = &mut buf[..ENC_SECRET_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    secrets[..SECRET_SIZE].copy_from_slice(&client_read_server_secret(
        read_buf,
        client_keypair.secret(),
    )?);

    // Write encrypted server and client secret.
    secrets[SECRET_SIZE..].copy_from_slice(&rand::random::<[u8; 32]>());
    let msg_enc = ecies::encrypt(&server_pubkey, &[], &secrets).map_err(Encryption)?;
    conn.write_all(&msg_enc).await.map_err(Write)?;

    // Read encrypted client secret echo.
    let (server_secret, client_secret) = secrets.split_at(SECRET_SIZE);
    let read_buf = &mut buf[..ENC_SECRET_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    client_read_and_check_secret_echo(read_buf, client_keypair.secret(), client_secret)?;

    Ok((session_key(&client_secret, &server_secret), server_pubkey))
}

fn client_read_server_secret(buf: &[u8], client_keypair_secret: &Secret) -> Result<Vec<u8>> {
    ecies::decrypt(client_keypair_secret, &[], buf).map_err(Error::Decryption)
}

fn client_read_and_check_secret_echo(
    buf: &[u8],
    client_keypair_secret: &Secret,
    client_secret: &[u8],
) -> Result<()> {
    use Error::{Decryption, EchoMismatch};

    let client_secret_echo = ecies::decrypt(client_keypair_secret, &[], buf).map_err(Decryption)?;
    if client_secret_echo != client_secret {
        return Err(EchoMismatch);
    }
    Ok(())
}

pub async fn server_handshake<RW: AsyncRead + AsyncWrite + Unpin>(
    mut conn: RW,
    server_keypair: &KeyPair,
) -> Result<([u8; 32], Public)> {
    use Error::*;

    let mut buf = [0u8; MAX_SERVER_READ_SIZE];

    // Write public key.
    conn.write_all(server_keypair.public().as_bytes())
        .await
        .map_err(Write)?;

    // Read public key.
    let read_buf = &mut buf[..PUBKEY_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    let client_pubkey = read_pubkey(read_buf)?;

    // Write encrypted server secret.
    let server_secret: [u8; 32] = rand::random();
    let server_secret_enc =
        ecies::encrypt(&client_pubkey, &[], &server_secret).map_err(Encryption)?;
    conn.write_all(&server_secret_enc).await.map_err(Write)?;

    // Read server secret echo and client secret.
    let read_buf = &mut buf[..2 * SECRET_SIZE + ENC_META_LEN];
    conn.read_exact(read_buf).await.map_err(Read)?;
    let secrets = server_read_and_check_secrets(read_buf, server_keypair.secret(), &server_secret)?;
    let client_secret = &secrets[SECRET_SIZE..];

    // Write encrypted client secret echo.
    let client_secret_enc =
        ecies::encrypt(&client_pubkey, &[], &client_secret).map_err(Encryption)?;
    conn.write_all(&client_secret_enc).await.map_err(Write)?;

    Ok((session_key(client_secret, &server_secret), client_pubkey))
}

fn read_pubkey(buf: &[u8]) -> Result<Public> {
    // FIXME(ross): There should be a method in the secp256k1 package for creating a Ge from a byte
    // slice (and probably also more convenient constructors similar to this for the Fe type).
    let mut x = Fe::default();
    x.set_b32(&buf[..32]);
    let mut y = Fe::default();
    y.set_b32(&buf[32..]);
    let mut point = Ge::default();
    point.set_xy(&x, &y);
    if !point.is_valid_var() {
        return Err(Error::InvalidPubkey);
    }

    Ok(Public::from_slice(buf))
}

fn server_read_and_check_secrets(
    buf: &[u8],
    server_keypair_secret: &Secret,
    server_secret: &[u8],
) -> Result<Vec<u8>> {
    use Error::{Decryption, EchoMismatch};

    let msg = ecies::decrypt(server_keypair_secret, &[], buf).map_err(Decryption)?;
    if &msg[..SECRET_SIZE] != server_secret {
        return Err(EchoMismatch);
    }
    Ok(msg)
}

fn session_key(client_secret: &[u8], server_secret: &[u8]) -> [u8; 32] {
    let mut session_key = [0u8; 32];
    for (i, b) in session_key.iter_mut().enumerate() {
        *b = client_secret[i] ^ server_secret[i];
    }
    session_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{ChannelRW, ChunkedRW};
    use parity_crypto::publickey::{Generator, Random};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn successful_symmetric_handshake() {
        let alice_keypair = Random.generate();
        let bob_keypair = Random.generate();

        let mut listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connect_fut =
            TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port));
        let accept_fut = listener.accept();
        let (connect_res, accept_res) = future::join(connect_fut, accept_fut).await;
        let mut client_stream = connect_res.unwrap();
        let (mut server_stream, _) = accept_res.unwrap();

        let (alice_res, bob_res) = future::join(
            handshake(&mut client_stream, &alice_keypair, None),
            handshake(&mut server_stream, &bob_keypair, None),
        )
        .await;

        let (alice_secret, alice_peer_pubkey) = alice_res.unwrap();
        let (bob_secret, bob_peer_pubkey) = bob_res.unwrap();

        assert_eq!(alice_secret, bob_secret);
        assert_eq!(&alice_peer_pubkey, bob_keypair.public());
        assert_eq!(&bob_peer_pubkey, alice_keypair.public());
    }

    #[test]
    fn successful_handshake() {
        let client_keypair = Random.generate();
        let server_keypair = Random.generate();

        let client_keypair_clone = client_keypair.clone();
        let server_keypair_clone = server_keypair.clone();

        let (client_rw, server_rw) = {
            let (client_rw, server_rw) = ChannelRW::new_pair();
            let max_chunk_size = 32;
            (
                ChunkedRW::new(client_rw, max_chunk_size),
                ChunkedRW::new(server_rw, max_chunk_size),
            )
        };

        let client_handle = std::thread::spawn(move || {
            futures::executor::block_on(client_handshake(client_rw, &client_keypair_clone, None))
        });
        let server_handle = std::thread::spawn(move || {
            futures::executor::block_on(server_handshake(server_rw, &server_keypair_clone))
        });

        let client_res = client_handle.join().unwrap();
        let server_res = server_handle.join().unwrap();

        assert!(client_res.is_ok());
        let (client_session_key, server_pubkey_output) = client_res.unwrap();
        assert!(server_res.is_ok());
        let (server_session_key, client_pubkey_output) = server_res.unwrap();
        assert_eq!(&client_pubkey_output, client_keypair.public());
        assert_eq!(&server_pubkey_output, server_keypair.public());
        assert_eq!(client_session_key, server_session_key);
    }

    #[test]
    fn read_client_pubkey_error() {
        let mut buf = [0u8; PUBKEY_SIZE];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        assert!(read_pubkey(&buf).is_err());
    }

    #[test]
    fn read_server_secret_key_error() {
        let client_keypair = Random.generate();
        let secret = client_keypair.secret();
        let mut buf = [0u8; ENC_SECRET_SIZE];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        assert!(client_read_server_secret(&buf[..ENC_SECRET_SIZE - 1], secret).is_err());
        assert!(client_read_server_secret(&buf, secret).is_err());
    }

    #[test]
    fn read_secrets_error() {
        let server_keypair = Random.generate();
        let secret = server_keypair.secret();
        let server_secret: [u8; SECRET_SIZE] = rand::random();

        // Invalid encryption.
        let mut buf = [0u8; 2 * SECRET_SIZE + ENC_META_LEN];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        assert!(matches!(
            server_read_and_check_secrets(&buf, secret, &server_secret).unwrap_err(),
            Error::Decryption(_)
        ));

        // Invalid echo.
        let msg_enc = ecies::encrypt(server_keypair.public(), &[], &buf[..2 * SECRET_SIZE])
            .expect("encrypting secret");
        assert!(matches!(
            server_read_and_check_secrets(&msg_enc, secret, &server_secret).unwrap_err(),
            Error::EchoMismatch
        ));
    }

    #[test]
    fn read_client_secret_echo_error() {
        let client_keypair = Random.generate();
        let secret = client_keypair.secret();
        let client_secret: [u8; SECRET_SIZE] = rand::random();

        // Invalid encryption.
        let mut buf = [0u8; ENC_SECRET_SIZE];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        assert!(matches!(
            client_read_and_check_secret_echo(&buf, secret, &client_secret).unwrap_err(),
            Error::Decryption(_)
        ));

        // Invalid echo.
        let msg_enc = ecies::encrypt(client_keypair.public(), &[], &buf[..2 * SECRET_SIZE])
            .expect("encrypting secret");
        assert!(matches!(
            client_read_and_check_secret_echo(&msg_enc, secret, &client_secret).unwrap_err(),
            Error::EchoMismatch
        ));
    }
}
