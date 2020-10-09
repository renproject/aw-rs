//! # Handshake protocol
//!
//! The following steps define the handshake protocol between a client and a server. When referring
//! to public keys and elliptic curves, the curve being used is the secp256k1 curve. When referring
//! to ECIES, the symmetric encryption used is AES-128 in CTR mode.
//!
//! 1. The client initiates the handshake by sending their public key to the server as plaintext.
//!    The public key is encoded as `(x, y)` where `x` and `y` are the cartesian coordintes of the
//!    curve point that represents the public key, and are individually represented as 32 byte
//!    integers in big endian format. This first message is thus 64 bytes in length.
//! 2. Upon receiving the public key from the client, the server picks a secret 32 byte value
//!    `server_secret` randomly, and encrypts it using ECIES under the client's public key. This
//!    encrypted secret is then sent to the client.
//! 3. The client receives and decrypts `server_secret`. The client then picks a secret 32 byte
//!    value `client_secret` randomly, and then encrypts `server_secret | client_secret` using
//!    ECIES under the server's public key. This encrypted message is sent to the server.
//! 4. The server decrypts the message from the client, which should be 64 bytes, and interprets
//!    the first 32 bytes as `server_secret_echo`, and the last 32 bytes as `client_secret`.  The
//!    server checks whether `server_secret_echo == server_secret`, and if this is not true the
//!    handshake fails. The server then encrypts `client_secret` under the client's public key and
//!    sends the encrypted message to the client. At this stage the server considers the handshake
//!    to have completed successfully.
//! 5. The client decrypts the 32 byte message from the server, which we will denote as
//!    `client_secret_echo`. The client checks that `client_secret_echo == client_secret`, and if
//!    this is not true the handshake fails. Otherwise the handshake protocol terminates. At this
//!    stage the client considers the handshake to have completed successfully.

use parity_crypto::publickey::{self, ecies, KeyPair, Public, Secret};
use secp256k1::group::{fe::Fe, Ge};
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    EchoMismatch,
    InvalidPubkey,
}

pub type Result<T> = std::result::Result<T, Error>;

pub async fn client_handshake<RW: AsyncRead + AsyncWrite + Unpin>(
    mut conn: RW,
    client_keypair: &KeyPair,
    server_pubkey: &Public,
) -> Result<[u8; 32]> {
    use Error::*;

    let mut buf = [0u8; MAX_CLIENT_READ_SIZE];

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
    let msg_enc = ecies::encrypt(server_pubkey, &[], &secrets).map_err(Encryption)?;
    conn.write_all(&msg_enc).await.map_err(Write)?;

    // Read encrypted client secret echo.
    let (server_secret, client_secret) = secrets.split_at(SECRET_SIZE);
    let read_buf = &mut buf[..ENC_SECRET_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    client_read_and_check_secret_echo(read_buf, client_keypair.secret(), client_secret)?;

    Ok(session_key(&client_secret, &server_secret))
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

    // Read public key.
    let read_buf = &mut buf[..PUBKEY_SIZE];
    conn.read_exact(read_buf).await.map_err(Read)?;
    let client_pubkey = server_read_client_pubkey(read_buf)?;

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

fn server_read_client_pubkey(buf: &[u8]) -> Result<Public> {
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
            futures::executor::block_on(client_handshake(
                client_rw,
                &client_keypair_clone,
                server_keypair_clone.public(),
            ))
        });
        let server_handle = std::thread::spawn(move || {
            futures::executor::block_on(server_handshake(server_rw, &server_keypair))
        });

        let client_res = client_handle.join().unwrap();
        let server_res = server_handle.join().unwrap();

        assert!(client_res.is_ok());
        let client_session_key = client_res.unwrap();
        assert!(server_res.is_ok());
        let (server_session_key, pubkey) = server_res.unwrap();
        assert_eq!(&pubkey, client_keypair.public());
        assert_eq!(client_session_key, server_session_key);
    }

    #[test]
    fn read_client_pubkey_error() {
        let mut buf = [0u8; PUBKEY_SIZE];
        for b in buf.iter_mut() {
            *b = rand::random();
        }
        assert!(server_read_client_pubkey(&buf).is_err());
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
