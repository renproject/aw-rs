use aes_gcm::aead::{self, generic_array::GenericArray, Aead};
use aes_gcm::Aes256Gcm;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[macro_export]
macro_rules! aes256gcm_encrypted_len {
    ($e:expr) => {
        NONCE_SIZE + $e + TAG_SIZE
    };
}

pub fn length_and_aes_encode(
    dst: &mut [u8],
    msg: &[u8],
    cipher: &Aes256Gcm,
) -> Result<(), aead::Error> {
    dst[4..].copy_from_slice(encrypt_aes256gcm(cipher, msg)?.as_slice());
    add_length_prefix(dst);
    Ok(())
}

pub fn add_length_prefix(msg: &mut [u8]) {
    let l: u32 = msg[4..].len() as u32;
    let l_prefix = l.to_be_bytes();
    msg[..4].copy_from_slice(&l_prefix);
}

pub fn encrypt_aes256gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that this
    // is safe, and also look into whether it will be better to generate the nonce in a
    // deterministic way so that both peers can determine the correct nonce locally.
    let nonce = rand::random::<[u8; 12]>();
    let nonce = GenericArray::from_slice(&nonce);
    let enc = cipher.encrypt(nonce, msg)?;
    let mut ret = Vec::with_capacity(nonce.len() + enc.len());
    ret.extend_from_slice(&nonce);
    ret.extend_from_slice(&enc);
    Ok(ret)
}

pub fn decrypt_aes256gcm(cipher: &Aes256Gcm, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO(ross): Currently the nonce is appended to the encrypted message. Double check that this
    // is safe, and also look into whether it will be better to generate the nonce in a
    // deterministic way so that both peers can determine the correct nonce locally.
    let (nonce, enc) = msg.split_at(12);
    let nonce = GenericArray::from_slice(&nonce);
    cipher.decrypt(nonce, enc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::typenum::marker_traits::Unsigned;
    use aes_gcm::aead::{AeadInPlace, NewAead};

    #[test]
    fn ciphertext_length() {
        let max_len = 256;
        let mut msg = Vec::with_capacity(max_len);
        for l in 1..=max_len {
            msg.clear();
            msg.resize_with(l, Default::default);
            let key: [u8; 32] = rand::random();
            let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));

            let ct = encrypt_aes256gcm(&cipher, &msg).unwrap();
            let expected_len = <Aes256Gcm as AeadInPlace>::NonceSize::to_usize()
                + l
                + <Aes256Gcm as AeadInPlace>::TagSize::to_usize();
            assert_eq!(ct.len(), expected_len);
        }
    }

    #[test]
    fn encryption_decryption() {
        let key: [u8; 32] = rand::random();
        let cipher = aes_gcm::AesGcm::new(GenericArray::from_slice(&key));
        let msg = b"this is a message";
        let ct = encrypt_aes256gcm(&cipher, msg).unwrap();
        let pt = dbg!(decrypt_aes256gcm(&cipher, &ct)).unwrap();
        assert_eq!(&pt, msg);
    }
}
