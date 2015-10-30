use std::collections::HashMap;
use std::collections::VecDeque;
use simple_crypto_lib::Mode;
use simple_crypto_lib::{crack, symm, utils};

static RANDOM_PREFIX: &'static str = "";//"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
static SECRET_KEY: &'static str = "c61afa6d692cd4897fef9b444e0b2c82";
static SECRET_STRING: &'static str =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll\
    cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encrypt_with_chosen_plaintext(chosen_plain_text: &Vec<u8>) -> Vec<u8> {
    // AES-128-ECB(random-prefix || your-string || unknown-string, random-key)
    let mut random_prefix = utils::from_base64(&String::from(RANDOM_PREFIX));
    let mut chosen_plain_text = chosen_plain_text.to_owned();
    let mut secret_plain_text = utils::from_base64(&String::from(SECRET_STRING));
    random_prefix.append(&mut chosen_plain_text);
    random_prefix.append(&mut secret_plain_text);

    let crypter = symm::AesEcbMode::new(utils::from_hex(&String::from(SECRET_KEY)));
    crypter.encrypt(&random_prefix)
}

pub fn decrypt_ecb(blocksize: usize) -> Vec<u8> {
    let mut plain_text: Vec<u8> = Vec::with_capacity(blocksize);
    let mut index_queue: VecDeque<u8> = vec![65u8; blocksize - 1].into_iter().collect();
    let mut block_id: usize = 0;

    loop {
        // decrypt unknow-string one byte at a time
        for i in 0..blocksize {
            // prepare block for indexing
            match plain_text[..].last() {
                Some(&byte) => {
                    index_queue.pop_front();
                    index_queue.push_back(byte);
                },
                _ => (),
            }
            //debug(&index_queue.iter().map(|elem| *elem).collect());

            // create dictionary
            let mut dict: HashMap<String, u8> = HashMap::with_capacity(255);
            for byte in 0..255 {
                index_queue.push_back(byte);
                let block = index_queue.iter().map(|elem| *elem).collect();
                dict.insert(get_block_as_hex(&block, 0).unwrap(), byte);
                index_queue.pop_back();
            }

            // prepare padding block
            let padding = vec![65u8; 15 - i];
            //debug(&padding);

            // decrypt byte
            let block = get_block_as_hex(&padding, block_id);
            if block.is_none() { return plain_text; }
            plain_text.push(*dict.get(&block.unwrap()).unwrap());
        }
        block_id += 1;
    }
}

pub fn decrypt_secret_string() -> String {
    // discover blocksize
    let blocksize = find_blocksize();
    // detect ecb
    assert_eq!(is_ecb_mode(), true);

    utils::to_ascii(&decrypt_ecb(blocksize))
}

pub fn get_block_as_hex(block: &Vec<u8>, at: usize) -> Option<String> {
    let at = at * 16;
    let cipher_text = encrypt_with_chosen_plaintext(&block);
    if cipher_text.len() < at + 16 { return None; }
    let block = cipher_text[at..(at + 16)].to_vec();
    Some(utils::to_hex(&block))
}

pub fn find_blocksize() -> usize {
    let mut chosen_plain_text = Vec::new();
    let base_cipher_text_len = encrypt_with_chosen_plaintext(&chosen_plain_text).len();
    loop {
        chosen_plain_text.push(0u8);
        let cipher_text_len = encrypt_with_chosen_plaintext(&chosen_plain_text).len();
        if cipher_text_len > base_cipher_text_len {
            return cipher_text_len - base_cipher_text_len;
        }
    }
}

pub fn is_ecb_mode() -> bool {
    let chosen_plain_text = vec![0u8; 16 * 3];
    let cipher_text = encrypt_with_chosen_plaintext(&chosen_plain_text);
    crack::aes::contains_duplicate_blocks(cipher_text)
}

pub fn debug(vec: &Vec<u8>) {
    let mut debug = String::new();
    for byte in vec {
        debug.push(*byte as char);
    }
    println!("{};", debug);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_blocksize() {
        assert_eq!(find_blocksize(), 16);
    }

    #[test]
    fn test_is_ecb_mode() {
        assert_eq!(is_ecb_mode(), true);
    }

    #[test]
    fn test_decrypt_ecb() {
        let expected =
            "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby \
            waving just to say hi\nDid you stop? No, I just drove by\n\u{4}\u{4}\u{4}\u{4}\u{4}\
            \u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}\u{4}";
        assert_eq!(decrypt_secret_string(), expected);
    }
}
