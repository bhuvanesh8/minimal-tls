use std::os::raw::c_void;
use std::mem;
use std::ptr;
use structures::{HandshakeMessage, TLSError};
use serialization::{u8_bytevec_as_bytes, u16_bytevec_as_bytes, TLSToBytes};

extern crate openssl;
use self::openssl::sign::Signer;
use self::openssl::pkey::PKey;
use self::openssl::ec::EcKey;
use self::openssl::hash::MessageDigest;

extern crate byteorder;
use self::byteorder::{NetworkEndian, WriteBytesExt};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn gen_server_random() -> Result<[u8; 32], TLSError> {
	let mut ret = [0; 32];
    unsafe { randombytes_buf(&mut ret as *mut _ as *mut c_void, 32) };
    Ok(ret)
}

// FIXME: Consider using sodium_malloc to allocate buffers for secret data, so they are
// marked to not be saved to the pagefile, and come with build-in guard page protection

// FIXME: Check return value on libsodium functions

pub fn x25519_key_exchange(client_pub : &Vec<u8>) -> Result<Vec<u8>, TLSError> {

    let mut secretkey : Vec<u8> = vec![0; unsafe{ crypto_box_publickeybytes() }];
    let mut publickey : Vec<u8> = vec![0; unsafe{ crypto_box_secretkeybytes() }];
    let mut scalarmult : Vec<u8> = vec![0; unsafe{ crypto_scalarmult_bytes() }];

    // Generate our secret key and public key
    unsafe { randombytes_buf(&mut secretkey as *mut _ as *mut c_void, secretkey.len()) };
    unsafe { crypto_scalarmult_base(publickey.as_mut_ptr(), secretkey.as_ptr()) };

    // Derive our shared key
    if unsafe { crypto_scalarmult(scalarmult.as_mut_ptr(), secretkey.as_ptr(), client_pub.as_ptr()) } != 0 {
        return Err(TLSError::InvalidKeyExchange);
    }

    // Check for the all zero value
    if scalarmult.iter().fold(0, |sum, x| sum | x) == 0 {
        return Err(TLSError::InvalidKeyExchange);
    }

    Ok(scalarmult)
}

// Both of these functions are taken from RFC 5869
pub fn hkdf_extract(salt: &Vec<u8>, ikm: &Vec<u8>) -> Result<Vec<u8>, TLSError> {
	let mut result : Vec<u8> = vec![0; unsafe { crypto_auth_hmacsha256_bytes() }];
	unsafe { crypto_auth_hmacsha256(result.as_mut_ptr(), ikm.as_ptr(), ikm.len() as u64, salt.as_ptr()) };

	Ok(result)
}

pub fn hkdf_expand(prk: &Vec<u8>, info: &Vec<u8>, length : usize) -> Result<Vec<u8>, TLSError> {
	let mut result : Vec<u8> = Vec::with_capacity(length);

	let hashlen = unsafe { crypto_auth_hmacsha256_bytes() };

	let n = ((length as f64) / (hashlen as f64)).ceil() as usize;

	(1..n).fold(vec![0; hashlen], |prev, x| {
		let mut curr : Vec<u8> = vec![0; hashlen];
		let mut buffer = Vec::with_capacity(prev.len() + info.len() + 1);
		buffer.extend(prev);
		buffer.extend(info);
		buffer.push(x as u8);
		unsafe { crypto_auth_hmacsha256(curr.as_mut_ptr(), prk.as_ptr(), prk.len() as u64, buffer.as_ptr()) };
		result.extend(&curr);
		curr
	});

	Ok(result)
}

pub fn hkdf_expand_label(secret: &Vec<u8>, label : &Vec<u8>, hashvalue : &Vec<u8>, length : u16) -> Result<Vec<u8>, TLSError> {
	let mut buffer : Vec<u8> = vec![];
	let mut fulllabel : Vec<u8> = label.clone();
	fulllabel.extend("TLS 1.3, ".as_bytes());

	// Serialize a HkdfLabel struct directly to the buffer
	buffer.write_u16::<NetworkEndian>(length).unwrap();
	buffer.extend(u16_bytevec_as_bytes(&fulllabel));
	buffer.extend(u8_bytevec_as_bytes(hashvalue));

	hkdf_expand(&secret, &buffer, length as usize)
}

pub fn transcript_hash(messages : &Vec<HandshakeMessage>) -> Result<Vec<u8>, TLSError> {

	let mut buffer : Vec<u8> = vec![];

	// This must be uninitialized because we need to create a pointer to it to initialize it
	let mut state : crypto_hash_sha256_state = unsafe { mem::uninitialized() };
	let stateptr = &mut state as *mut crypto_hash_sha256_state;
	unsafe { crypto_hash_sha256_init(stateptr) };

	// Just combine all the messages in the hash
	for x in messages {
		let bytes : Vec<u8> = x.as_bytes();
		unsafe { crypto_hash_sha256_update(stateptr, bytes.as_ptr(), bytes.len() as u64) };
	}

	unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

	Ok(buffer)
}

pub fn derive_secret(secret: &Vec<u8>, label : &Vec<u8>, messages : &Vec<HandshakeMessage>) -> Result<Vec<u8>, TLSError> {
	hkdf_expand_label(secret, label, &try!(transcript_hash(messages)), unsafe { crypto_auth_hmacsha256_bytes() } as u16)
}

pub fn derive_secret_hashstate(secret: &Vec<u8>, label : &Vec<u8>, th_state : &crypto_hash_sha256_state) -> Result<Vec<u8>, TLSError> {

	// Copy the hash state struct
	let mut th_copy : crypto_hash_sha256_state = unsafe { mem::uninitialized() };
	let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;
	unsafe { ptr::copy_nonoverlapping(th_state, stateptr, mem::size_of::<crypto_hash_sha256_state>()) };

	// Finalize the hash
	let mut buffer : Vec<u8> = vec![];
	unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

	hkdf_expand_label(secret, label, &buffer, unsafe { crypto_auth_hmacsha256_bytes() } as u16)
}

pub fn generate_early_secret() -> Result<Vec<u8>, TLSError> {
	let hashlen = unsafe { crypto_auth_hmacsha256_bytes() };
	hkdf_extract(&vec![0; hashlen], &vec![0; hashlen])
}

pub fn generate_derived_secret(earlysecret : &Vec<u8>) -> Result<Vec<u8>, TLSError> {
	derive_secret(earlysecret, &Vec::from("derived secret"), &vec![])
}

pub fn generate_handshake_secret(shared_key : &Vec<u8>, derivedsecret: &Vec<u8>) -> Result<Vec<u8>, TLSError> {
	hkdf_extract(derivedsecret, shared_key)
}

pub fn generate_shts(hs_secret : &Vec<u8>, th_state: &crypto_hash_sha256_state) -> Result<Vec<u8>, TLSError> {
	derive_secret_hashstate(hs_secret, &Vec::from("server handshake traffic secret"), &th_state)
}

pub fn generate_cert_signature(private_key: &PKey, th_state : &crypto_hash_sha256_state) -> Result<Vec<u8>, TLSError> {

	// Copy the hash state struct
	let mut th_copy : crypto_hash_sha256_state = unsafe { mem::uninitialized() };
	let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;
	unsafe { ptr::copy_nonoverlapping(th_state, stateptr, mem::size_of::<crypto_hash_sha256_state>()) };

	// Finalize the hash
	let mut buffer : Vec<u8> = vec![];
	unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

	// Sign the buffer
	let mut signer = try!(Signer::new(MessageDigest::sha256(), private_key).or(Err(TLSError::SignatureError)));
	try!(signer.update(vec![0x20; 64].as_slice()).or(Err(TLSError::SignatureError)));
	try!(signer.update(&Vec::from("TLS 1.3, server CertificateVerify")).or(Err(TLSError::SignatureError)));
	try!(signer.update(vec![0].as_slice()).or(Err(TLSError::SignatureError)));
	try!(signer.update(buffer.as_slice()).or(Err(TLSError::SignatureError)));

	Ok(try!(signer.finish().or(Err(TLSError::SignatureError))))
}

pub fn generate_finished(hs_secret : &Vec<u8>, th_state : &crypto_hash_sha256_state) -> Result<Vec<u8>, TLSError> {
	let finished_key = try!(hkdf_expand_label(&hs_secret,
		&Vec::from("finished"), &vec![], unsafe { crypto_auth_hmacsha256_bytes() } as u16));

	// Copy the hash state struct
	let mut th_copy : crypto_hash_sha256_state = unsafe { mem::uninitialized() };
	let stateptr = &mut th_copy as *mut crypto_hash_sha256_state;
	unsafe { ptr::copy_nonoverlapping(th_state, stateptr, mem::size_of::<crypto_hash_sha256_state>()) };

	// Finalize the hash
	let mut buffer : Vec<u8> = vec![];
	unsafe { crypto_hash_sha256_final(stateptr, buffer.as_mut_ptr()) };

	let mut result : Vec<u8> = vec![0; unsafe { crypto_auth_hmacsha256_bytes() }];
	unsafe { crypto_auth_hmacsha256(result.as_mut_ptr(), buffer.as_ptr(), buffer.len() as u64, finished_key.as_ptr()) };

	Ok(result)
}
                
pub fn generate_satf(derived_secret : &Vec<u8>, th_state : &crypto_hash_sha256_state) -> Result<Vec<u8>, TLSError> {
	
    let mastersecret = try!(hkdf_extract(derived_secret, &vec![0; unsafe{ crypto_auth_hmacsha256_bytes() }]));
    derive_secret_hashstate(&mastersecret, &Vec::from("server application traffic secret"), th_state)
}

pub fn generate_traffic_keyring(secret : &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), TLSError> {
    let write_key = try!(hkdf_expand_label(secret, &Vec::from("key"), &Vec::from(""), unsafe { crypto_aead_chacha20poly1305_ietf_keybytes() } as u16)); 
    let write_iv = try!(hkdf_expand_label(secret, &Vec::from("iv"), &Vec::from(""), unsafe { crypto_aead_chacha20poly1305_ietf_npubbytes() } as u16));
    Ok((write_key, write_iv))
}

pub fn generate_nonce(sequence_number : u64, aead_iv : &Vec<u8>) -> Result<Vec<u8>, TLSError> {
    let mut buffer = vec![0; 4];
	buffer.write_u64::<NetworkEndian>(sequence_number).unwrap();
    Ok((1..buffer.len()).map(|x| buffer[x] ^ aead_iv[x]).collect())
}

pub fn aead_encrypt(write_key : &Vec<u8>, nonce : &Vec<u8>, plaintext : &Vec<u8>) -> Result<Vec<u8>, TLSError> {
    
    // Buffer for ciphertext
    let mut buffer : Vec<u8> = vec![0; plaintext.len() + unsafe { crypto_aead_chacha20poly1305_ietf_abytes() }];
    let mut buffer_len : u64 = 0;
    unsafe { crypto_aead_chacha20poly1305_ietf_encrypt(buffer.as_mut_ptr(), &mut buffer_len, plaintext.as_ptr(), plaintext.len() as u64, ptr::null(), 0, ptr::null(), nonce.as_ptr(), write_key.as_ptr()) };

    Ok(buffer)
}

// FIXME: TLS cookie should use HMAC-SHA256 to encode the hash of ClientHello1 when sending HelloRetryRequest
