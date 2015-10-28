use simple_crypto_lib::xor;

pub fn break_sb_xor_cipher(encrypted_data: &Vec<u8>) -> u8 {
    xor::break_xor_cipher(encrypted_data, 1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::{hex, ascii, xor};

    #[test]
    fn test_break_sb_xor_cipher() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let encrypted_data = hex::from_hex(&mut String::from(hex));
        let k = break_sb_xor_cipher(&encrypted_data);
        let key = xor::key_from_u8(k);
        let decrypted_data = xor::xor_cipher(&key, &encrypted_data);
        let message = ascii::to_ascii(&decrypted_data);
        assert_eq!(k as char, 'X');
        assert_eq!(message, String::from("Cooking MC's like a pound of bacon"));
    }
}
