
pub fn has_valid_padding(bytes: &Vec<u8>) -> bool {
    let padding = bytes[bytes.len() - 1] as usize;
    if padding > 16 || padding < 1 { return false; }
    for i in 0..padding {
        if bytes[bytes.len() - i - 1] as usize != padding {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_crypto_lib::utils;

    #[test]
    fn test_unpad() {
        let test = "ICE ICE BABY\x04\x04\x04\x04";
        assert!(has_valid_padding(&utils::from_ascii(&String::from(test))));
        let test = "ICE ICE BABY\x05\x05\x05\x05";
        assert!(!has_valid_padding(&utils::from_ascii(&String::from(test))));
        let test = "ICE ICE BABY\x01\x02\x03\x04";
        assert!(!has_valid_padding(&utils::from_ascii(&String::from(test))));
        assert!(has_valid_padding(&vec![16; 16]));
    }
}
