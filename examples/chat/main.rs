use aw::message::{Header, To, GOSSIP_PEER_ID};
use aw::{conn_manager, util, ConnectionManager};
use parity_crypto::publickey;
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::convert::TryFrom;
use std::env;
use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

mod alias;
mod message;
mod tui;

use alias::Aliases;
use tui::ScreenText;

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
    let own_pubkey = *keypair.public();

    let max_connections = 10;
    let max_header_len = 512;
    let max_data_len = 2048;
    let buffer_size = 100;
    let alpha = 3;
    let will_pull = move |header: &Header| {
        header.to == aw::id_from_pubkey(&own_pubkey) || header.to == GOSSIP_PEER_ID
    };
    let (aw_fut, conn_manager, _port, aw_in, mut aw_out) = aw::new_aw_task(
        keypair.clone(),
        port,
        will_pull,
        max_connections,
        max_header_len,
        max_data_len,
        buffer_size,
        alpha,
    )
    .expect("creating aw task");
    let aw_handle = tokio::spawn(aw_fut);

    let mut screen = ScreenText::new();
    tui::init_screen();
    let aliases = Aliases::new();
    let aliases_clone = aliases.clone();
    let screen_clone = screen.clone();
    tokio::task::spawn_blocking(move || {
        read_input(&conn_manager, aw_in, aliases_clone, keypair, screen_clone)
    });

    while let Some((_, msg)) = aw_out.recv().await {
        let msg = message::Message::try_from(msg.as_slice()).expect("TODO");
        let string = match aliases.get_by_pubkey(&msg.from) {
            Some(name) => format!("{}: {}", name, msg.message),
            None => format!("{}: {}", msg.from, msg.message),
        };
        screen.add_output_line(string);
        screen.print_screen();
    }

    aw_handle.await.unwrap().unwrap();
}

fn read_input(
    conn_manager: &Arc<Mutex<ConnectionManager>>,
    mut sender: mpsc::Sender<(To, Vec<u8>, Vec<u8>)>,
    mut aliases: Aliases,
    keypair: KeyPair,
    mut screen: ScreenText,
) {
    use termios::{tcsetattr, Termios, ECHO, ICANON, TCSANOW};
    let termios = Termios::from_fd(libc::STDIN_FILENO).unwrap();
    let mut new_termios = termios.clone();
    new_termios.c_lflag &= !(ICANON | ECHO);
    tcsetattr(libc::STDIN_FILENO, TCSANOW, &mut new_termios).unwrap();

    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    loop {
        let mut buf = [0u8; 1];
        lock.read_exact(&mut buf).unwrap();
        if buf[0] as char == '\n' {
            let output = match parse_input(
                conn_manager,
                &mut sender,
                &mut aliases,
                &keypair,
                &screen.input(),
            ) {
                Ok(s) => s,
                Err(e) => format!("{:?}", e),
            };
            screen.add_output_line(output);
            screen.clear_input();
        } else if buf[0] == 0x7f {
            screen.backspace();
        } else {
            screen.add_stdin_char(buf[0] as char);
        }
        screen.print_screen();
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
    conn_manager: &Arc<Mutex<ConnectionManager>>,
    sender: &mut mpsc::Sender<(To, Vec<u8>, Vec<u8>)>,
    aliases: &mut Aliases,
    keypair: &KeyPair,
    input: &str,
) -> Result<String, ParseError> {
    if input.starts_with("/") && !input.starts_with("//") {
        return futures::executor::block_on(parse_command(
            conn_manager,
            aliases,
            keypair,
            input.strip_prefix("/").unwrap(),
        ));
    }

    if input.starts_with("@") {
        let (peer, msg) = {
            let trimmed = &input[1..];
            let i = trimmed.find(" ").ok_or(ParseError::InvalidInput)?;
            let (peer, msg) = (&trimmed[..i], &trimmed[i + 1..]);
            (
                aliases
                    .pubkey_from_maybe_alias(peer)
                    .map_err(|_| ParseError::InvalidInput)?,
                msg,
            )
        };
        let message =
            message::Message::new_from_pubkey_and_bytes(*keypair.public(), msg.as_bytes())
                .map_err(|_| ParseError::InvalidInput)?;
        if let Err(_) = sender.try_send((
            To::Peer(peer),
            message::key(msg.as_bytes()).to_vec(),
            message.into(),
        )) {
            println!(
                "error: not connected to peer {}",
                publickey::public_to_address(&peer)
            );
        }
        return Ok(format!(">{}", msg));
    }

    if input.starts_with("#") {
        // TODO(ross): Subnet message.
    }

    if input.starts_with("*") {
        let msg = input[1..].as_bytes().to_owned();
        let msg_string = std::str::from_utf8(&msg).unwrap().to_owned();
        let mut full_msg = keypair.public().as_bytes().to_vec();
        full_msg.extend_from_slice(&msg);
        if let Err(_) = sender.try_send((To::Gossip, message::key(&msg).to_vec(), full_msg)) {
            println!("error: could not gossip message");
        }
        return Ok(format!(">{}", msg_string));
    }

    Err(ParseError::InvalidInput)
}

async fn parse_command(
    conn_manager: &Arc<Mutex<ConnectionManager>>,
    aliases: &mut Aliases,
    keypair: &KeyPair,
    command: &str,
) -> Result<String, ParseError> {
    use ParseError::*;

    let mut words = command.split_ascii_whitespace();
    let command = words.next().ok_or(InvalidCommand)?;

    match command {
        "info" => {
            let property = words.next().ok_or(InvalidArguments)?;
            match property {
                "pubkey" => Ok(format!("{:x?}", keypair.public())),
                "id" => Ok(format!("{}", base64::encode(keypair.public().as_bytes()))),
                "address" => Ok(format!("{:?}", keypair.address())),
                "peers" => {
                    let lock = util::get_lock(conn_manager);
                    if lock.num_peers() == 0 {
                        return Ok("not connected to any peers".to_owned());
                    }
                    let mut string = String::new();
                    string.push_str(
                        "________________________________________________________________\n",
                    );
                    string.push_str(
                        "| Address                                    | IP              |\n",
                    );
                    string.push_str(
                        "|--------------------------------------------|-----------------|\n",
                    );
                    for (pubkey, addr) in lock.peers() {
                        string.push_str(&format!(
                            "| {:x?} | {} |\n",
                            publickey::public_to_address(pubkey),
                            addr
                        ));
                    }
                    string.push_str(
                        "|____________________________________________|_________________|",
                    );
                    Ok(string)
                }
                _ => Err(InvalidArguments),
            }
        }
        "add" => {
            let mut conn_manager_lock = match conn_manager.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let pubkey = {
                let pubkey = words.next().ok_or(InvalidArguments)?;
                aliases
                    .pubkey_from_maybe_alias(pubkey)
                    .map_err(|_| ParseError::InvalidInput)?
            };
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager_lock.add_unsigned_peer(pubkey, addr);
            Ok("peer added!".to_owned())
        }
        "connect" => {
            let pubkey = {
                let pubkey = words.next().ok_or(InvalidArguments)?;
                aliases
                    .pubkey_from_maybe_alias(pubkey)
                    .map_err(|_| ParseError::InvalidInput)?
            };
            let addr = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| SocketAddr::from_str(s).map_err(|_| InvalidArguments))?;
            conn_manager::establish_connection(conn_manager, keypair, &pubkey, addr, None)
                .await
                .map_err(|_| CommandFailed)?;
            Ok("connected to peer!".to_owned())
        }
        "alias" => {
            let pubkey = words
                .next()
                .ok_or(InvalidArguments)
                .and_then(|s| Public::from_str(s).map_err(|_| InvalidArguments))?;
            let name = words.next().ok_or(InvalidArguments).map(str::to_string)?;
            let _ = aliases.insert(name, pubkey);
            Ok("alias added!".to_owned())
        }
        _ => Err(InvalidCommand),
    }
}
