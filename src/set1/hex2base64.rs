use simple_crypto_lib::utils;

pub fn hex2base64(hex: &mut String) -> String {
    let bytes = utils::from_hex(&hex);
    utils::to_base64(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex2base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(hex2base64(&mut String::from(hex)), String::from(expected));
    }
}
