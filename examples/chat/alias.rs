use aw::util;
use parity_crypto::publickey::Public;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub struct Aliases(Arc<Mutex<Inner>>);

impl Aliases {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Inner::new())))
    }

    pub fn insert(&mut self, name: String, pubkey: Public) {
        let mut lock = util::get_lock(self.0.as_ref());
        lock.insert(name, pubkey)
    }

    pub fn get_by_pubkey(&self, pubkey: &Public) -> Option<String> {
        let lock = util::get_lock(self.0.as_ref());
        lock.get_by_pubkey(pubkey).cloned()
    }

    pub fn pubkey_from_maybe_alias(&self, name: &str) -> Result<Public, <Public as FromStr>::Err> {
        let lock = util::get_lock(self.0.as_ref());
        lock.pubkey_from_maybe_alias(name)
    }
}

impl Clone for Aliases {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct Inner {
    by_pubkey: HashMap<Public, String>,
    by_name: HashMap<String, Public>,
}

impl Inner {
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

    fn pubkey_from_maybe_alias(&self, name: &str) -> Result<Public, <Public as FromStr>::Err> {
        match self.get_by_name(name) {
            Some(pubkey) => Ok(pubkey.to_owned()),
            None => Public::from_str(name),
        }
    }
}
