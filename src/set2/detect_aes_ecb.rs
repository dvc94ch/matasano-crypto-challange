use std::io::{BufRead, BufReader};
use std::fs::File;

use simple_crypto_lib::{crack, utils};

pub fn detect_ecb(filename: &'static str) -> Option<String> {
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    for mut line in reader.lines().filter_map(|res| res.ok()) {
        let bytes = utils::from_hex(&mut line);
        if crack::aes::contains_duplicate_blocks(bytes) {
            return Some(line);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecb() {
        let expect =
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b\
            0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc\
            06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d\
            403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(detect_ecb("data/aes_detect.txt"), Some(String::from(expect)));
    }
}
