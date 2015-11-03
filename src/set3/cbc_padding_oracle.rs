use rand;
use simple_crypto_lib::{Mode, Padder};
use simple_crypto_lib::{aes, padder, symm, utils, xor};
use set2::pkcs7_padding_validation::has_valid_padding;

pub fn encrypted_data() -> Vec<u8> {
    let messages = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ];
    let index: usize = rand::random::<usize>() % messages.len();
    let key = utils::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::AesCbcMode::new(key);
    aes.encrypt(&utils::from_base64(&String::from(messages[index])))
}

struct NoUnpadding;
impl Padder for NoUnpadding {}

pub fn validate(cipher_text: &Vec<u8>) -> bool {
    let key = utils::from_ascii(&String::from("YELLOW SUBMARINE"));
    let aes = symm::CbcMode::new(aes::AesCipher::new(key), NoUnpadding {});
    let dec = aes.decrypt(&cipher_text[..]);

    has_valid_padding(&dec)
}

pub fn crack() -> String {
    let bytes = encrypted_data();
    let mut p: Vec<u8> = Vec::new();
    let mut last_block = vec![0u8; 16];
    for block in utils::BlockIter::new(bytes) {
        let iv = find_iv(&block);
        let mut decrypted_block = decrypt_block(&iv[..], &last_block[..]);
        p.append(&mut decrypted_block);
        last_block = block[..].to_vec();
    }
    let padder = padder::Pkcs7Padder::new(16);
    utils::to_ascii(&padder.unpad(&p[16..p.len()]))
}

pub fn find_iv(c: &[u8; 16]) -> Vec<u8> {
    let mut iv = vec![65u8; 16];
    iv.append(&mut c.to_vec());
    assert_eq!(iv.len(), 32);

    for i in 0..16 {

        for j in 0..255 {
            iv[15 - i] = j;
            let valid = validate(&iv);
            if valid { break; }
        }

        if i < 15 {
            for j in 0..(i + 1) {
                iv[15 - j] ^= ((i + 1) ^ (i + 2)) as u8;
            }
        }
    }
    iv[0..16].to_vec()
}

pub fn decrypt_block(iv: &[u8], c: &[u8]) -> Vec<u8> {
    xor::xor(&xor::xor(iv, &[16; 16])[..], c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate() {
        let bytes = encrypted_data();
        println!("{}", bytes.len());
        assert!(validate(&bytes));
    }

    #[test]
    fn test_crack() {
        //assert_eq!(crack(), "");
    }
}
