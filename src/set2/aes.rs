use simple_crypto_lib::{ascii, base64, file, symm};
use simple_crypto_lib::symm::Mode;

pub fn decrypt_aes(filename: &'static str) -> String {
    let mut buffer = file::file_to_buffer(filename);
    let bytes = base64::from_base64(&mut buffer);
    let key = ascii::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::AesEcbMode::new(key);
    let bytes = aes.decrypt(&bytes);
    ascii::to_ascii(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::file;

    #[test]
    fn test_decrypt_aes() {
        let message = decrypt_aes("data/aes.txt");
        let buffer = file::file_to_buffer("data/solution.txt");
        assert_eq!(message, buffer);
    }
}
