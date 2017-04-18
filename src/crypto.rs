use structures::{TLSError};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// FIXME: Have to look up how to get high quality rng on every platform
pub fn gen_server_random() -> Result<[u8; 32], TLSError> {
	Ok([0; 32])
}
