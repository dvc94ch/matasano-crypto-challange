use std::io::{BufRead, BufReader};
use std::fs::File;

use simple_crypto_lib::{hex, blockiter};

pub fn detect_ecb(filename: &'static str) -> Option<String> {
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    for mut line in reader.lines().filter_map(|res| res.ok()) {
        let bytes = hex::from_hex(&mut line);
        let mut block_vec: Vec<[u8; 16]> = Vec::new();
        for new_block in blockiter::BlockIter::new(bytes) {
            for block in &block_vec {
                if block == &new_block {
                    return Some(hex::to_hex(&block.to_vec()));
                }
            }
            block_vec.push(new_block);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecb() {
        assert_eq!(detect_ecb("data/aes_detect.txt"), Some(String::from("08649af70dc06f4fd5d2d69c744cd283")));
    }
}
