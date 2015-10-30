use simple_crypto_lib::Mode;
use simple_crypto_lib::{symm, utils};

static SECRET_KEY: &'static str = "90431260cfc515e6cc94199eeccaf045";

pub fn profile_for(email: String) -> Vec<u8> {
    let mut encoded_string = String::from("email=");
    for c in email.chars() {
        if c == '&' || c == '=' {
            continue;
        }
        encoded_string.push(c);
    }
    encoded_string = encoded_string + "&uid=10&role=user";

    let key = utils::from_hex(&String::from(SECRET_KEY));
    let aes = symm::AesEcbMode::new(key);
    let bytes = utils::from_ascii(&encoded_string);
    aes.encrypt(&bytes)
}

pub fn decrypt_profile_for(bytes: Vec<u8>) -> String {
    let key = utils::from_hex(&String::from(SECRET_KEY));
    let aes = symm::AesEcbMode::new(key);
    let bytes = aes.decrypt(&bytes);
    utils::to_ascii(&bytes)
}

pub fn create_admin_profile() -> Vec<u8> {
    // email needs to be 13 chars long to offset the admin part into a separate block
    let email = String::from("dvc@craven.ch");
    // fake email needs to have 10 chars to offset admin block
    let fake_email = String::from("abcdefghij") + "admin\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04";
    let mut profile = profile_for(email)[0..32].to_vec();
    let mut admin_block = profile_for(fake_email)[16..32].to_vec();
    profile.append(&mut admin_block);
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_for() {
        let cipher_text = profile_for(String::from("abcd"));
        let plain_text = decrypt_profile_for(cipher_text);
        assert_eq!(plain_text, "email=abcd&uid=10&role=user");
    }

    #[test]
    fn test_ecb_copy_paste() {
        let cipher_text = create_admin_profile();
        let plain_text = decrypt_profile_for(cipher_text);
        assert_eq!(plain_text, "email=dvc@craven.ch&uid=10&role=admin");
    }
}
