use simple_crypto_lib::{ascii, base64, xor, file};

pub fn break_mb_xor_file(filename: &'static str) -> String {
    let mut buffer = file::file_to_buffer(filename);
    let bytes = base64::from_base64(&mut buffer);
    let keysize = xor::find_keysize(&bytes);
    let key = xor::break_xor_cipher(&bytes, keysize);
    let decrypted_bytes = xor::xor_cipher(&key, &bytes);
    ascii::to_ascii(&decrypted_bytes)
}

pub fn break_mb_xor(bytes: &Vec<u8>) -> String {
    let keysize = xor::find_keysize(&bytes);
    let key = xor::break_xor_cipher(&bytes, keysize);
    let decrypted_bytes = xor::xor_cipher(&key, &bytes);
    println!("{} {}", bytes.len(), decrypted_bytes.len());
    ascii::to_ascii(&decrypted_bytes)
}



#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::{base64, file};

    #[test]
    fn test_break_mb_xor_file() {
        // keysize: 29
        // key: Terminator X: Bring the noise
        let mut msg = break_mb_xor_file("data/break_mb_xor.txt");
        // base64 doesn't pop padding because of newlines
        msg.pop();
        let expected = file::file_to_buffer("data/solution.txt");
        assert_eq!(expected, msg);
    }

    #[test]
    fn test_break_mb_xor() {
        let buffer = "CzY3JyorLmNiLC5paSojaToqPGMkIC1iPWM0PComImMkJydlJyooKy8gQwplLixlKjEkMzplPisgJ2MMaSsgKDFlKGMmMC4nKC8";
        let expected = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let bytes = base64::from_base64(&String::from(buffer));
        assert_eq!(super::break_mb_xor(&bytes), expected);
    }
}
