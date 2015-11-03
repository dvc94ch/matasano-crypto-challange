use simple_crypto_lib::Mode;
use simple_crypto_lib::{symm, utils};

pub fn encrypt_profile(chosen_plain_text: String) -> Vec<u8> {
    let plain_text = String::from("comment1=cooking%20MCs;userdata=") +
        &utils::escape(chosen_plain_text, vec![';', '='])[..] +
        ";comment2=%20like%20a%20pound%20of%20bacon";
    let key = utils::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::AesCbcMode::new(key);
    aes.encrypt(&utils::from_ascii(&plain_text))
}

pub fn is_admin(cipher_text: Vec<u8>) -> bool {
    let key = utils::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::AesCbcMode::new(key);
    let plain_text = aes.decrypt(&cipher_text);
    println!("{}", utils::to_ascii(&plain_text));
    utils::to_ascii(&plain_text).contains(";admin=true;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin() {
        assert!(!is_admin(encrypt_profile(String::from(";admin=true;"))));
    }

    #[test]
    fn test_bitflip() {
        let input =
            "xxxxxxxxxxxxxxxx\
             xxxxx9admin9true";
        let mut bytes = encrypt_profile(String::from(input));
        // offset iv block
        bytes[48 + 5] ^= ';' as u8 ^ '9' as u8;
        bytes[48 + 11] ^= '=' as u8 ^ '9' as u8;
        assert!(is_admin(bytes));
    }
}
