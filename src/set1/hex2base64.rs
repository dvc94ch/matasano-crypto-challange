use simple_crypto_lib::{base64, hex};

pub fn hex2base64(hex: &mut String) -> String {
    let bytes = hex::from_hex(&hex);
    base64::to_base64(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    static HEX: &'static str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    static BASE64: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    #[test]
    fn test_hex2base64() {
        assert_eq!(hex2base64(&mut String::from(HEX)), String::from(BASE64));
    }
}
