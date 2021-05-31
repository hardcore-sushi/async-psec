use std::convert::TryInto;
use hkdf::Hkdf;
use hmac::{Hmac, NewMac, Mac};
use sha2::Sha384;

pub const HASH_OUTPUT_LEN: usize = 48; //SHA384
const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 12;

pub fn iv_to_nonce(iv: &[u8], counter: &mut usize) -> Vec<u8> {
    let mut counter_bytes = vec![0; 4];
    counter_bytes.extend_from_slice(&counter.to_be_bytes());
    let r: Vec<u8> = iv.iter().zip(counter_bytes.iter()).map(|(a, b)| a^b).collect();
    *counter += 1;
    r
}

fn hkdf_expand_label(key: &[u8], label: &str, context: Option<&[u8]>, okm: &mut [u8]) {
    let mut info: Vec<u8> = [&(label.len() as u32).to_be_bytes(), label.as_bytes()].concat();
    if let Some(context) = context {
        info.extend([&(context.len() as u32).to_be_bytes(), context].concat());
    }
    let hkdf = Hkdf::<Sha384>::from_prk(key).unwrap();
    hkdf.expand(&info, okm).unwrap();
}

fn get_labels(handshake: bool, i_am_bob: bool) -> (String, String) {
    let mut label = if handshake {
        "handshake"
    } else {
        "application"
    }.to_owned();
    label += "_i_am_";
    let local_label = label.clone() + if i_am_bob {
        "bob"
    } else {
        "alice"
    };
    let peer_label = label + if i_am_bob {
        "alice"
    } else {
        "bob"
    };
    (local_label, peer_label)
}

pub struct HandshakeKeys {
    pub local_key: [u8; KEY_LEN],
    pub local_iv: [u8; IV_LEN],
    pub local_handshake_traffic_secret: [u8; HASH_OUTPUT_LEN],
    pub peer_key: [u8; KEY_LEN],
    pub peer_iv: [u8; IV_LEN],
    pub peer_handshake_traffic_secret: [u8; HASH_OUTPUT_LEN],
    pub handshake_secret: [u8; HASH_OUTPUT_LEN],
}

impl HandshakeKeys {
    pub fn derive_keys(shared_secret: [u8; 32], handshake_hash: [u8; HASH_OUTPUT_LEN], i_am_bob: bool) -> HandshakeKeys {
        let (handshake_secret, _) = Hkdf::<Sha384>::extract(None, &shared_secret);

        let (local_label, peer_label) = get_labels(true, i_am_bob);

        let mut local_handshake_traffic_secret = [0; HASH_OUTPUT_LEN];
        hkdf_expand_label(handshake_secret.as_slice(), &local_label, Some(&handshake_hash), &mut local_handshake_traffic_secret);

        let mut peer_handshake_traffic_secret = [0; HASH_OUTPUT_LEN];
        hkdf_expand_label(handshake_secret.as_slice(), &peer_label, Some(&handshake_hash), &mut peer_handshake_traffic_secret);

        let mut local_handshake_key = [0; KEY_LEN];
        hkdf_expand_label(&local_handshake_traffic_secret, "key", None, &mut local_handshake_key);
        let mut local_handshake_iv = [0; IV_LEN];
        hkdf_expand_label(&local_handshake_traffic_secret, "iv", None, &mut local_handshake_iv);
    
        let mut peer_handshake_key = [0; KEY_LEN];
        hkdf_expand_label(&peer_handshake_traffic_secret, "key", None, &mut peer_handshake_key);
        let mut peer_handshake_iv = [0; IV_LEN];
        hkdf_expand_label(&peer_handshake_traffic_secret,"iv", None, &mut peer_handshake_iv);

        HandshakeKeys {
            local_key: local_handshake_key,
            local_iv: local_handshake_iv,
            local_handshake_traffic_secret: local_handshake_traffic_secret,
            peer_key: peer_handshake_key,
            peer_iv: peer_handshake_iv,
            peer_handshake_traffic_secret: peer_handshake_traffic_secret,
            handshake_secret: handshake_secret.as_slice().try_into().unwrap(),
        }
    }
}

pub struct ApplicationKeys {
    pub local_key: [u8; KEY_LEN],
    pub local_iv: [u8; IV_LEN],
    pub peer_key: [u8; KEY_LEN],
    pub peer_iv: [u8; IV_LEN],
}

impl ApplicationKeys {
    pub fn derive_keys(handshake_secret: [u8; HASH_OUTPUT_LEN], handshake_hash: [u8; HASH_OUTPUT_LEN], i_am_bob: bool) -> ApplicationKeys {
        let mut derived_secret = [0; HASH_OUTPUT_LEN];
        hkdf_expand_label(&handshake_secret, "derived", None, &mut derived_secret);
        let (master_secret, _) = Hkdf::<Sha384>::extract(Some(&derived_secret), b"");

        let (local_label, peer_label) = get_labels(false, i_am_bob);
        
        let mut local_application_traffic_secret = [0; HASH_OUTPUT_LEN];
        hkdf_expand_label(&master_secret, &local_label, Some(&handshake_hash), &mut local_application_traffic_secret);
    
        let mut peer_application_traffic_secret = [0; HASH_OUTPUT_LEN];
        hkdf_expand_label(&master_secret, &peer_label, Some(&handshake_hash), &mut peer_application_traffic_secret);

        let mut local_application_key = [0; KEY_LEN];
        hkdf_expand_label(&local_application_traffic_secret, "key", None, &mut local_application_key);
        let mut local_application_iv = [0; IV_LEN];
        hkdf_expand_label(&local_application_traffic_secret, "iv", None, &mut local_application_iv);
    
        let mut peer_application_key = [0; KEY_LEN];
        hkdf_expand_label(&peer_application_traffic_secret, "key", None, &mut peer_application_key);
        let mut peer_application_iv = [0; IV_LEN];
        hkdf_expand_label(&peer_application_traffic_secret,"iv", None, &mut peer_application_iv);

        ApplicationKeys {
            local_key: local_application_key,
            local_iv: local_application_iv,
            peer_key: peer_application_key,
            peer_iv: peer_application_iv,
        }
    }
}

pub fn compute_handshake_finished(local_handshake_traffic_secret: [u8; HASH_OUTPUT_LEN], handshake_hash: [u8; HASH_OUTPUT_LEN]) -> [u8; HASH_OUTPUT_LEN] {
    let mut finished_key = [0; HASH_OUTPUT_LEN];
    hkdf_expand_label(&local_handshake_traffic_secret, "finished", None, &mut finished_key);
    let mut hmac = Hmac::<Sha384>::new_from_slice(&finished_key).unwrap();
    hmac.update(&handshake_hash);
    hmac.finalize().into_bytes().as_slice().try_into().unwrap()
}

pub fn verify_handshake_finished(peer_handshake_finished: [u8; HASH_OUTPUT_LEN], peer_handshake_traffic_secret: [u8; HASH_OUTPUT_LEN], handshake_hash: [u8; HASH_OUTPUT_LEN]) -> bool {
    let mut peer_finished_key = [0; HASH_OUTPUT_LEN];
    hkdf_expand_label(&peer_handshake_traffic_secret, "finished", None, &mut peer_finished_key);
    let mut hmac = Hmac::<Sha384>::new_from_slice(&peer_finished_key).unwrap();
    hmac.update(&handshake_hash);
    hmac.verify(&peer_handshake_finished).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{IV_LEN, HASH_OUTPUT_LEN};
    use rand::{Rng, RngCore, rngs::OsRng};

    #[test]
    fn iv_to_nonce() {
        let mut iv = [0; IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let mut counter = OsRng.gen();

        let mut counters = Vec::with_capacity(1000);
        let mut nonces = Vec::with_capacity(1000);
        for _ in 0..1000 {
            counters.push(counter);
            let nonce = super::iv_to_nonce(&iv, &mut counter);

            assert!(!counters.contains(&counter));
            assert!(!nonces.contains(&nonce));

            nonces.push(nonce);
        }
    }

    #[test]
    fn get_labels() {
        let (hl, hp) = super::get_labels(true, true);
        assert_eq!(hl, "handshake_i_am_bob");
        assert_eq!(hp, "handshake_i_am_alice");

        let (al, ap) = super::get_labels(false, false);
        assert_eq!(al, "application_i_am_alice");
        assert_eq!(ap, "application_i_am_bob");
    }

    #[test]
    fn hkdf_expand_label() {
        let key = "Hardcore Music is the best music. You can't deny";
        let mut okm = [0; HASH_OUTPUT_LEN];
        super::hkdf_expand_label(key.as_bytes(), "the_label", Some(b"the_context"), &mut okm);
        assert_eq!(hex::encode(okm), "108b05132cfdb9416be7a63763eda8e834b2235556b36aab5ced2cac15d7d2c24fb1d579a8c5de5c9cd5d2a357545bbf");
    }
}