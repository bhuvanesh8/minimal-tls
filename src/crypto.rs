use std::os::raw::c_void;
use std::mem;
use std::ptr;
use structures::{HandshakeMessage, TLSError, HandshakeType, HandshakeBytes};
use serialization::{u8_bytevec_as_bytes, TLSToBytes};

extern crate openssl;
use self::openssl::sign::Signer;
use self::openssl::pkey::PKey;
use self::openssl::hash::MessageDigest;

extern crate byteorder;
use self::byteorder::{NetworkEndian, WriteBytesExt};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Crypto buffer size constants
const auth_hmacsha256_bytes: usize = 32;
const hash_sha256_bytes: usize = 32;
const aead_chacha20poly1305_bytes: usize = 32;
const aead_chacha20poly1305_npubbytes: usize = 12;
const aead_chacha20poly1305_abytes: usize = 16;

pub fn gen_server_random() -> Result<[u8; 32], TLSError> {
    let mut ret = [0; 32];
    unsafe { randombytes_buf(&mut ret as *mut _ as *mut c_void, 32) };
    Ok(ret)
}

// FIXME: Consider using sodium_malloc to allocate buffers for secret data, so they are
// marked to not be saved to the pagefile, and come with build-in guard page protection

// FIXME: Check return value on libsodium functions

pub fn x25519_key_exchange(client_pub: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TLSError> {

    let mut secretkey: Vec<u8> = vec![0; unsafe{ crypto_box_secretkeybytes() }];
    let mut publickey: Vec<u8> = vec![0; unsafe{ crypto_box_publickeybytes() }];
    let mut scalarmult: Vec<u8> = vec![0; unsafe{ crypto_scalarmult_bytes() }];

    // Generate our secret key and public key
    unsafe { randombytes_buf(secretkey.as_mut_ptr() as *mut c_void, secretkey.len()) };
    unsafe { crypto_scalarmult_curve25519_base(publickey.as_mut_ptr(), secretkey.as_ptr()) };

    // Derive our shared key
    if unsafe {
           crypto_scalarmult_curve25519(scalarmult.as_mut_ptr(),
                                        secretkey.as_ptr(),
                                        client_pub.as_ptr())
       } != 0 {
        return Err(TLSError::InvalidKeyExchange);
    }

    // Check for the all zero value
    if scalarmult.iter().fold(0, |sum, x| sum | x) == 0 {
        return Err(TLSError::InvalidKeyExchange);
    }

    Ok((scalarmult, publickey))
}

// Both of these functions are taken from RFC 5869
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, TLSError> {
    let mut result: Vec<u8> = vec![0; auth_hmacsha256_bytes];

    unsafe {
        crypto_auth_hmacsha256(result.as_mut_ptr(),
                               ikm.as_ptr(),
                               ikm.len() as u64,
                               salt.as_ptr())
    };

    Ok(result)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, TLSError> {
    let mut result: Vec<u8> = Vec::with_capacity(length);

    let hashlen = auth_hmacsha256_bytes;

    let mut n: usize = length / hashlen;
    if length % hashlen > 0 {
        n += 1;
    }

    (0..n).fold(vec![], |prev, x| {
        let mut curr = vec![0; hashlen];
        let mut buffer = Vec::with_capacity(prev.len() + info.len() + 1);
        buffer.extend(prev.iter());
        buffer.extend(info.iter());
        buffer.push((x + 1) as u8);
        unsafe {
            crypto_auth_hmacsha256(curr.as_mut_ptr(),
                                   buffer.as_ptr(),
                                   buffer.len() as u64,
                                   prk.as_ptr())
        };
        result.extend(curr.iter());
        curr
    });

    result.truncate(length);
    Ok(result)
}

pub fn hkdf_expand_label(secret: &[u8],
                         label: &[u8],
                         hashvalue: &[u8],
                         length: u16)
                         -> Result<Vec<u8>, TLSError> {
    let mut buffer: Vec<u8> = vec![];
    let mut fulllabel: Vec<u8> = Vec::from("tls13 ");
    fulllabel.extend(label.iter());

    // Serialize a HkdfLabel struct directly to the buffer
    buffer.write_u16::<NetworkEndian>(length).unwrap();
    buffer.extend(u8_bytevec_as_bytes(&fulllabel).iter());
    buffer.extend(u8_bytevec_as_bytes(hashvalue).iter());

    hkdf_expand(secret, &buffer, length as usize)
}

pub fn transcript_hash(messages: &[HandshakeMessage]) -> Result<Vec<u8>, TLSError> {

    let mut buffer: Vec<u8> = vec![0; auth_hmacsha256_bytes];

    // This must be uninitialized because we need to create a pointer to it to initialize it
    let mut state: crypto_hash_sha256_state = unsafe { mem::uninitialized() };
    let stateptr = &mut state as *mut crypto_hash_sha256_state;
    unsafe { crypto_hash_sha256_init(stateptr) };

    // Just combine all the messages in the hash
    for x in messages {

        // Look up type
        let msg_type = match *x {
            HandshakeMessage::ClientHello(_) => HandshakeType::ClientHello,
            HandshakeMessage::ServerHello(_) => HandshakeType::ServerHello,
            HandshakeMessage::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            HandshakeMessage::EndOfEarlyData(_) => HandshakeType::EndOfEarlyData,
            HandshakeMessage::HelloRetryRequest(_) => HandshakeType::HelloRetryRequest,
            HandshakeMessage::CertificateRequest(_) => HandshakeType::CertificateRequest,
            HandshakeMessage::Certificate(_) => HandshakeType::Certificate,
            HandshakeMessage::CertificateVerify(_) => HandshakeType::CertificateVerify,
            HandshakeMessage::Finished(_) => HandshakeType::Finished,
            _ => return Err(TLSError::InvalidTHMessage),
        };

        let hs_msg = HandshakeBytes {
            msg_type: msg_type,
            length: 0,
            body: x.as_bytes(),
        };
        let bytes: Vec<u8> = hs_msg.as_bytes();
        unsafe { crypto_hash_sha256_update(stateptr, bytes.as_ptr(), bytes.len() as u64) };
    }

    unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

    Ok(buffer)
}

pub fn derive_secret(secret: &[u8],
                     label: &[u8],
                     messages: &[HandshakeMessage])
                     -> Result<Vec<u8>, TLSError> {
    let ret = try!(transcript_hash(messages));
    hkdf_expand_label(secret, label, &ret, ret.len() as u16)
}

impl Clone for crypto_hash_sha256_state {
    fn clone(&self) -> crypto_hash_sha256_state {
        crypto_hash_sha256_state {
            state: self.state,
            count: self.count,
            buf: self.buf,
        }
    }
}

pub fn derive_secret_hashstate(secret: &[u8],
                               label: &[u8],
                               th_state: &crypto_hash_sha256_state)
                               -> Result<Vec<u8>, TLSError> {

    // Copy the hash state struct
    let mut th_copy = (*th_state).clone();
    let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;

    // Finalize the hash
    let mut buffer = [0; hash_sha256_bytes];
    unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

    hkdf_expand_label(secret, label, &buffer, buffer.len() as u16)
}

pub fn generate_early_secret() -> Result<Vec<u8>, TLSError> {
    hkdf_extract(&[0; auth_hmacsha256_bytes], &[0; auth_hmacsha256_bytes])
}

pub fn generate_derived_secret(secret: &[u8]) -> Result<Vec<u8>, TLSError> {
    derive_secret(secret, b"derived", &[])
}

pub fn generate_handshake_secret(shared_key: &[u8],
                                 derivedsecret: &[u8])
                                 -> Result<Vec<u8>, TLSError> {
    hkdf_extract(derivedsecret, shared_key)
}

pub fn generate_hts(hs_secret: &[u8],
                    th_state: &crypto_hash_sha256_state)
                    -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    let server_hts = try!(derive_secret_hashstate(hs_secret, b"s hs traffic", th_state));
    let client_hts = try!(derive_secret_hashstate(hs_secret, b"c hs traffic", th_state));

    Ok((server_hts, client_hts))
}

pub fn generate_cert_signature(private_key: &PKey,
                               th_state: &crypto_hash_sha256_state)
                               -> Result<Vec<u8>, TLSError> {

    // Copy the hash state struct
    let mut th_copy = (*th_state).clone();
    let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;

    // Finalize the hash
    let mut buffer = [0; hash_sha256_bytes];
    unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

    // Sign the buffer
    let mut signer = try!(Signer::new(MessageDigest::sha256(), private_key)
                              .or(Err(TLSError::SignatureError)));
    try!(signer
             .update(&[0x20; 64])
             .or(Err(TLSError::SignatureError)));
    try!(signer
             .update(b"TLS 1.3, server CertificateVerify")
             .or(Err(TLSError::SignatureError)));
    try!(signer.update(&[0]).or(Err(TLSError::SignatureError)));
    try!(signer.update(&buffer).or(Err(TLSError::SignatureError)));

    Ok(try!(signer.finish().or(Err(TLSError::SignatureError))))
}

pub fn generate_finished(hs_secret: &[u8],
                         th_state: &crypto_hash_sha256_state)
                         -> Result<Vec<u8>, TLSError> {
    let finished_key =
        try!(hkdf_expand_label(hs_secret, b"finished", &[], auth_hmacsha256_bytes as u16));

    // Copy the hash state struct
    let mut th_copy = (*th_state).clone();
    let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;

    // Finalize the hash
    let mut buffer = [0; hash_sha256_bytes];
    unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

    let mut result: Vec<u8> = vec![0; auth_hmacsha256_bytes];
    unsafe {
        crypto_auth_hmacsha256(result.as_mut_ptr(),
                               buffer.as_ptr(),
                               buffer.len() as u64,
                               finished_key.as_ptr())
    };

    Ok(result)
}

pub fn generate_atf(derived_secret: &[u8],
                    th_state: &crypto_hash_sha256_state)
                    -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    let mastersecret = try!(hkdf_extract(derived_secret, &[0; auth_hmacsha256_bytes]));
    Ok((try!(derive_secret_hashstate(&mastersecret, b"s ap traffic", th_state)),
        try!(derive_secret_hashstate(&mastersecret, b"c ap traffic", th_state))))
}

pub fn generate_traffic_keyring(secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    let key = try!(hkdf_expand_label(secret, b"key", &[], aead_chacha20poly1305_bytes as u16));
    let iv = try!(hkdf_expand_label(secret, b"iv", &[], aead_chacha20poly1305_npubbytes as u16));
    Ok((key, iv))
}

pub fn generate_nonce(sequence_number: u64, aead_iv: &[u8]) -> Result<Vec<u8>, TLSError> {
    let mut buffer = vec![0; aead_iv.len() - 8];
    buffer
        .write_u64::<NetworkEndian>(sequence_number)
        .unwrap();
    Ok((0..buffer.len())
           .map(|x| buffer[x] ^ aead_iv[x])
           .collect())
}

pub fn aead_encrypt(write_key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TLSError> {
    // Buffer for ciphertext
    let mut buffer: Vec<u8> = vec![0; plaintext.len() + aead_chacha20poly1305_abytes];
    let mut buffer_len: u64 = 0;
    unsafe {
        crypto_aead_chacha20poly1305_ietf_encrypt(buffer.as_mut_ptr(),
                                                  &mut buffer_len,
                                                  plaintext.as_ptr(),
                                                  plaintext.len() as u64,
                                                  ptr::null(),
                                                  0,
                                                  ptr::null(),
                                                  nonce.as_ptr(),
                                                  write_key.as_ptr())
    };

    Ok(buffer)
}

pub fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TLSError> {
    let mut buffer: Vec<u8> = vec![0; ciphertext.len()];
    let mut buffer_len: u64 = 0;

    if unsafe {
           crypto_aead_chacha20poly1305_ietf_decrypt(buffer.as_mut_ptr(),
                                                     &mut buffer_len,
                                                     ptr::null_mut(),
                                                     ciphertext.as_ptr(),
                                                     ciphertext.len() as u64,
                                                     ptr::null(),
                                                     0,
                                                     nonce.as_ptr(),
                                                     key.as_ptr())
       } != 0 {
        return Err(TLSError::AEADError);
    }
    Ok(buffer)
}

pub fn verify_finished(th_state: &crypto_hash_sha256_state,
                       hs_secret: &[u8],
                       verify_data: &[u8])
                       -> Result<(), TLSError> {
    let finished_key =
        try!(hkdf_expand_label(hs_secret, b"finished", &[], auth_hmacsha256_bytes as u16));

    // Copy the hash state struct
    let mut th_copy = (*th_state).clone();
    let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;

    // Finalize the hash
    let mut buffer = [0; hash_sha256_bytes];
    unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

    if unsafe {
           crypto_auth_hmacsha256_verify(verify_data.as_ptr(),
                                         buffer.as_ptr(),
                                         buffer.len() as u64,
                                         finished_key.as_ptr())
       } != 0 {
        Err(TLSError::AEADError)
    } else {
        Ok(())
    }
}

/*
    FIXME: TLS cookie should use HMAC-SHA256 to encode the hash of
    ClientHello1 when sending HelloRetryRequest
*/
