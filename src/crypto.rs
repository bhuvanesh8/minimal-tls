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
