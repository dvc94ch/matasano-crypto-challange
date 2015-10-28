use simple_crypto_lib::{xor, ascii, hex};

pub fn mb_xor_cipher(message: String, key: String) -> String {
    let data = ascii::from_ascii(&message);
    let key = ascii::from_ascii(&key);
    let encrypted_data = xor::xor_cipher(&key, &data);
    hex::to_hex(&encrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mb_xor_cipher() {
        let msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let expect = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(mb_xor_cipher(String::from(msg), String::from("ICE")), expect);
    }
}
