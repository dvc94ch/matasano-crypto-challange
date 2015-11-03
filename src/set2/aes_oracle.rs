use rand;

use simple_crypto_lib::Mode;
use simple_crypto_lib::{crack, symm, utils};

pub fn encryption_oracle() -> Box<Mode> {
    let key = utils::random_bytes(16);
    match rand::random() {
        true => box symm::AesEcbMode::new(key) as Box<Mode>,
        false => box symm::AesCbcMode::new(key) as Box<Mode>,
    }
}

pub fn detect_aes_mode() -> bool {
    let crypter = encryption_oracle();
    crack::aes::is_ecb_mode(crypter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aes_mode() {
        let mut ecb_mode = false;
        let mut cbc_mode = false;
        for _ in 0..10 {
            let mode = detect_aes_mode();
            println!("{}", mode);
            match mode {
                true => ecb_mode = true,
                false => cbc_mode = true,
            }
        }
        assert_eq!(ecb_mode, true);
        assert_eq!(cbc_mode, true);
    }
}
