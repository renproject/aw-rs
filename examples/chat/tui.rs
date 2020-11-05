use aw::util;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ScreenText(Arc<Mutex<(Vec<String>, String)>>);

impl ScreenText {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new((Vec::new(), String::new()))))
    }

    pub fn add_stdin_char(&mut self, c: char) {
        let mut lock = util::get_lock(&self.0);
        lock.1.push(c);
        advance_cursor();
    }

    pub fn backspace(&mut self) {
        let mut lock = util::get_lock(&self.0);
        lock.1.pop();
        retreat_cursor();
    }

    pub fn clear_input(&mut self) {
        let mut lock = util::get_lock(&self.0);
        lock.1.clear();
        cursor_start_of_line();
    }

    pub fn input(&self) -> String {
        let lock = util::get_lock(&self.0);
        lock.1.clone()
    }

    pub fn add_output_line(&mut self, s: String) {
        let mut lock = util::get_lock(&self.0);
        lock.0.push(s);
    }

    pub fn print_screen(&self) {
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

pub fn init_screen() {
    clear_screen();
    cursor_to_bottom();
    flush();
}

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
