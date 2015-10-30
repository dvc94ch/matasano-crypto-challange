use simple_crypto_lib::{utils, xor};

pub fn fixed_xor(hex1: &mut String, hex2: &mut String) -> String {
    let bytes1 = utils::from_hex(&hex1);
    let bytes2 = utils::from_hex(&hex2);
    utils::to_hex(&xor::xor(&bytes1, &bytes2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_xor() {
        let mut hex1 = String::from("1c0111001f010100061a024b53535009181c");
        let mut hex2 = String::from("686974207468652062756c6c277320657965");
        let expected = String::from("746865206b696420646f6e277420706c6179");
        let res = fixed_xor(&mut hex1, &mut hex2);
        assert_eq!(res, expected);
    }
}
