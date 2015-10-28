use rand;

use simple_crypto_lib::symm;

pub fn encryption_oracle(plain_text: Vec<u8>) -> Vec<u8> {
    let key = random_vec(16);
    let aes: Box<symm::Mode> = match rand::random() {
        true => box symm::AesEcbMode::new(key) as Box<symm::Mode>,
        false => box symm::AesCbcMode::new(key, [0u8; 16]) as Box<symm::Mode>,
    };
    aes.encrypt(&plain_text)
}

pub fn detect_aes_mode() -> bool {
    let plain_text = vec![0u8; 64];
    let cipher_text = encryption_oracle(plain_text);
    if &cipher_text[0..16] == &cipher_text[16..32] {
        true
    } else {
        false
    }
}

pub fn random_vec(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(rand::random::<u8>());
    }
    vec
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
