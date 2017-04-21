use std::os::raw::c_void;
use structures::{TLSError};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// FIXME: We MUST call sodium_init once before we start calling functions from the lib

// FIXME: Have to look up how to get high quality rng on every platform
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
	unsafe { crypto_auth_hmacsha512(result.as_mut_ptr(), ikm.as_ptr(), ikm.len() as u64, salt.as_ptr()) };

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
		unsafe { crypto_auth_hmacsha512(curr.as_mut_ptr(), prk.as_ptr(), prk.len() as u64, buffer.as_ptr()) };
		result.extend(&curr);
		curr
	});

	Ok(result)
}
