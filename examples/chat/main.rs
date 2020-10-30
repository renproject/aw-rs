use aw_rs::conn_manager::connection::ConnectionPool;
use aw_rs::conn_manager::peer_table::{self, PeerTable};
use aw_rs::conn_manager::{self, ConnectionManager};
use aw_rs::util;
use aw_rs::util::SharedPtr;
use parity_crypto::publickey;
use parity_crypto::publickey::{Generator, KeyPair, Public, Random};
use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

mod alias;

use alias::Aliases;

fn flush() {
    std::io::stdout().flush().unwrap();
}

fn clear_screen() {
    print!("\x1b[2J\x1b[1;1H");
}

fn cursor_to_bottom() {
    print!("\x1b[100E");
}

fn cursor_to_top() {
    print!("\x1b[H");
}

fn save_cursor_position() {
    print!("\x1b[s");
}

fn load_cursor_position() {
    print!("\x1b[u");
}

fn advance_cursor() {
    print!("\x1b[C");
}

fn retreat_cursor() {
    print!("\x1b[D");
}

fn cursor_start_of_line() {
    print!("\x1b[500D");
}

#[derive(Clone)]
struct ScreenText(Arc<Mutex<(Vec<String>, String)>>);

impl ScreenText {
    fn new() -> Self {
        Self(Arc::new(Mutex::new((Vec::new(), String::new()))))
    }

    fn add_stdin_char(&mut self, c: char) {
        let mut lock = util::get_lock(&self.0);
        lock.1.push(c);
        advance_cursor();
    }

    fn backspace(&mut self) {
        let mut lock = util::get_lock(&self.0);
        lock.1.pop();
        retreat_cursor();
    }

    fn clear_input(&mut self) {
        let mut lock = util::get_lock(&self.0);
        lock.1.clear();
        cursor_start_of_line();
    }

    fn input(&self) -> String {
        let lock = util::get_lock(&self.0);
        lock.1.clone()
    }

    fn add_output_line(&mut self, s: String) {
        let mut lock = util::get_lock(&self.0);
        lock.0.push(s);
    }

    fn print_screen(&self) {
        let lock = util::get_lock(&self.0);
        save_cursor_position();
        clear_screen();
        cursor_to_bottom();
        print!("{}", lock.1);
        cursor_to_top();
        for line in lock.0.iter() {
            println!("{}", line);
        }
        load_cursor_position();
        flush();
    }
}

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        eprintln!("too many arguments: expected 1, got {:?}", args.len() - 1);
        return;
    }
    let addr_str = args.pop().expect("address arg");
    let port = addr_str.parse().expect("invalid port argument");

    let mut screen = ScreenText::new();
    clear_screen();
    cursor_to_bottom();
    flush();

    let keypair = Random.generate();

    let max_connections = 10;
    let max_header_len = 512;
    let max_data_len = 2048;
    let buffer_size = 100;
    let (pool, mut reads) = ConnectionPool::new_with_max_connections_allocated(
        max_connections,
        max_header_len,
        max_data_len,
        buffer_size,
    );
    let table = PeerTable::new();
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new(pool, table)));

    let listen_handle = tokio::spawn(conn_manager::listen_for_peers(
        conn_manager.clone(),
        keypair.clone(),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        port,
    ));

    let aliases = Aliases::new();
    let aliases_clone = aliases.clone();
    let cm = conn_manager.clone();
    let screen_clone = screen.clone();
    tokio::task::spawn_blocking(move || read_input(cm, aliases_clone, keypair, screen_clone));

    while let Some((sender, msg)) = reads.recv().await {
        let pubkey_addr = publickey::public_to_address(&sender);
        let string = match aliases.get_by_pubkey(&sender) {
            Some(name) => format!("{}: {}", name, std::str::from_utf8(&msg).unwrap()),
            None => format!("{}: {}", pubkey_addr, std::str::from_utf8(&msg).unwrap()),
        };
        screen.add_output_line(string);
        screen.print_screen();
    }

    listen_handle.await.unwrap().unwrap();
}

fn read_input(
    conn_manager: SharedPtr<ConnectionManager>,
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
            let output = match parse_input(&conn_manager, &mut aliases, &keypair, &screen.input()) {
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
    conn_manager: &SharedPtr<ConnectionManager>,
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
        let conn_manager = conn_manager.clone();
        let (peer, msg) = {
            let trimmed = &input[1..];
            let i = trimmed.find(" ").ok_or(ParseError::InvalidInput)?;
            let (peer, msg) = (&trimmed[..i], &trimmed[i + 1..]);
            (
                aliases
                    .pubkey_from_maybe_alias(peer)
                    .map_err(|_| ParseError::InvalidInput)?,
                msg.as_bytes().to_owned(),
            )
        };
        let msg_string = std::str::from_utf8(&msg).unwrap().to_owned();
        tokio::spawn(async move {
            if let Err(_) = conn_manager::try_send_peer(&conn_manager, &peer, &msg).await {
                println!(
                    "error: not connected to peer {}",
                    publickey::public_to_address(&peer)
                );
            }
        });
        return Ok(format!(">{}", msg_string));
    }

    if input.starts_with("#") {
        // TODO(ross): Subnet message.
    }

    if input.starts_with("*") {
        let conn_manager = conn_manager.clone();
        let msg = input[1..].as_bytes().to_owned();
        let msg_string = std::str::from_utf8(&msg).unwrap().to_owned();
        tokio::spawn(async move {
            conn_manager::send_to_all(&conn_manager, &msg)
                .await
                .expect("TODO")
        });
        return Ok(format!(">{}", msg_string));
    }

    Err(ParseError::InvalidInput)
}

async fn parse_command(
    conn_manager: &SharedPtr<ConnectionManager>,
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
                "id" => Ok(format!(
                    "{:?}",
                    peer_table::id_from_pubkey(keypair.public())
                )),
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
            conn_manager_lock.add_peer(pubkey, addr);
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
            conn_manager::establish_connection(conn_manager, keypair, &pubkey, addr)
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
