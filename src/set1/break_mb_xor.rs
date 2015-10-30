use simple_crypto_lib::{crack, xor, utils};

pub fn break_mb_xor_file(filename: &'static str) -> String {
    let mut buffer = utils::file_to_buffer(filename);
    let bytes = utils::from_base64(&mut buffer);
    let keysize = crack::xor::find_keysize(&bytes);
    let key = crack::xor::break_xor_cipher(&bytes, keysize);
    let decrypted_bytes = xor::xor_cipher(&key, &bytes);
    utils::to_ascii(&decrypted_bytes)
}

pub fn break_mb_xor(bytes: &Vec<u8>) -> String {
    let keysize = crack::xor::find_keysize(&bytes);
    let key = crack::xor::break_xor_cipher(&bytes, keysize);
    let decrypted_bytes = xor::xor_cipher(&key, &bytes);
    println!("{} {}", bytes.len(), decrypted_bytes.len());
    utils::to_ascii(&decrypted_bytes)
}



#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::utils;

    #[test]
    fn test_break_mb_xor_file() {
        // keysize: 29
        // key: Terminator X: Bring the noise
        let mut msg = break_mb_xor_file("data/break_mb_xor.txt");
        // base64 doesn't pop padding because of newlines
        msg.pop();
        let expected = utils::file_to_buffer("data/solution.txt");
        assert_eq!(expected, msg);
    }

    #[test]
    fn test_break_mb_xor() {
        let buffer =
            "CzY3JyorLmNiLC5paSojaToqPGMkIC1iPWM0PComImMkJydlJyooKy8gQwplLixlKjEkMzplPisgJ2MMaSsgK\
            DFlKGMmMC4nKC8";
        let expected = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let bytes = utils::from_base64(&String::from(buffer));
        assert_eq!(super::break_mb_xor(&bytes), expected);
    }
}
