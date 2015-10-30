use simple_crypto_lib::Mode;
use simple_crypto_lib::{symm, utils};

pub fn decrypt_aes(filename: &'static str) -> String {
    let mut buffer = utils::file_to_buffer(filename);
    let bytes = utils::from_base64(&mut buffer);
    let key = utils::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::AesEcbMode::new(key);
    let bytes = aes.decrypt(&bytes);
    utils::to_ascii(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::utils;

    #[test]
    fn test_decrypt_aes() {
        let message = decrypt_aes("data/aes.txt");
        let buffer = utils::file_to_buffer("data/solution.txt");
        assert_eq!(message, buffer);
    }
}
