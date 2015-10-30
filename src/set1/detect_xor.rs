use std::fs::File;
use std::io::{BufReader, BufRead};
use simple_crypto_lib::{crack, utils, xor};

pub fn detect_xor(filename: &'static str) -> (String, String) {
    let reader = BufReader::new(File::open(filename).unwrap());

    let mut max_score = 0;
    let mut max_bytes = vec![0u8];

    for mut line in reader.lines().filter_map(|res| res.ok()) {
        let bytes = utils::from_hex(&mut line);
        let byte_freq = crack::analysis::byte_freq(&bytes);
        let score = byte_freq.iter().filter(|&(&_, &f)| f > 1).fold(0, |acc, (_, f)| acc + f);
        if score > max_score {
            max_score = score;
            max_bytes = bytes;
        }
    }
    let key = crack::xor::break_xor_cipher(&max_bytes, 1);
    let msg = xor::xor_cipher(&key, &max_bytes);
    (utils::to_ascii(&key), utils::to_ascii(&msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_xor() {
        let (key, message) = detect_xor("data/detect_xor.txt");
        assert_eq!(message, "Now that the party is jumping\n");
        assert_eq!(key, "5");
    }
}
