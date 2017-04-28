extern crate byteorder;
use self::byteorder::{NetworkEndian, WriteBytesExt};

use structures::{HandshakeMessage, TLSPlaintext, CipherSuite, Extension, CertificateEntry, SignatureScheme, KeyUpdateRequest, ASN1Cert, TLSInnerPlaintext, TLSCiphertext, KeyShare};

pub trait TLSToBytes {
	fn as_bytes(&self) -> Vec<u8>;
}

/*
	We can't use a generic Vec<T> implementation for these two functions
	because TLS 1.3 encodes length differently depending on the max length
	of the vector. If the cap is <= 255, it only uses one byte, but otherwise
	uses two bytes. I think this is really silly but oh well
*/

fn u16_vector_as_bytes<T>(data : &Vec<T>) -> Vec<u8> where T:TLSToBytes {
	let mut ret : Vec<u8> = vec![];
    let mut buf : Vec<u8> = vec![];
	for x in data.iter() {
		buf.extend(x.as_bytes().iter());
	}

	ret.write_u16::<NetworkEndian>(buf.len() as u16).unwrap();
    ret.extend(buf.iter());
	ret
}

pub fn u16_bytevec_as_bytes(data : &Vec<u8>) -> Vec<u8> {
	let mut ret : Vec<u8> = vec![];
	ret.write_u16::<NetworkEndian>(data.len() as u16).unwrap();
    ret.extend(data.iter());
	ret
}

fn u8_vector_as_bytes<T>(data : &Vec<T>) -> Vec<u8> where T:TLSToBytes {
	let mut ret : Vec<u8> = vec![];
    let mut buf : Vec<u8> = vec![];
	for x in data.iter() {
		buf.extend(x.as_bytes().iter());
	}

    ret.push(buf.len() as u8);
    ret.extend(buf.iter());
	ret
}

pub fn u8_bytevec_as_bytes(data : &Vec<u8>) -> Vec<u8> {
	let mut ret : Vec<u8> = vec![];
    ret.push(data.len() as u8);
    ret.extend(data.iter());
	ret
}

impl TLSToBytes for TLSPlaintext {
	fn as_bytes(&self) -> Vec<u8> {
    	let mut ret : Vec<u8> = Vec::new();

    	// Content type
    	ret.push(self.ctype as u8);

    	// Protocol version
    	ret.write_u16::<NetworkEndian>(self.legacy_record_version).unwrap();

    	// Data length
    	ret.write_u16::<NetworkEndian>(self.length).unwrap();

    	// Data
		ret.extend(self.fragment.clone().iter());

		ret
	}
}

impl TLSToBytes for TLSCiphertext {
	fn as_bytes(&self) -> Vec<u8> {
    	let mut ret : Vec<u8> = Vec::new();

    	// Content type
    	ret.push(self.opaque_type as u8);

    	// Protocol version
    	ret.write_u16::<NetworkEndian>(self.legacy_record_version).unwrap();

    	// Data length
    	ret.write_u16::<NetworkEndian>(self.length).unwrap();

    	// Data
		ret.extend(self.encrypted_record.clone().iter());

		ret
	}
}

impl TLSToBytes for TLSInnerPlaintext {
	fn as_bytes(&self) -> Vec<u8> {
    	let mut ret : Vec<u8> = Vec::new();

    	// Data length
    	ret.write_u16::<NetworkEndian>(self.content.len() as u16).unwrap();

    	// Data
		ret.extend(self.content.clone().iter());
    	
        // Content type
    	ret.push(self.ctype as u8);

        // Padding length
        ret.write_u16::<NetworkEndian>(self.zeros.len() as u16).unwrap();

        // Padding
        ret.extend(self.zeros.clone().iter());

		ret
	}
}

impl TLSToBytes for CipherSuite {
    fn as_bytes(&self) -> Vec<u8> {
        let mut ret : Vec<u8> = vec![];
        ret.write_u16::<NetworkEndian>(*self as u16).unwrap();
        ret
    }
}

impl TLSToBytes for CertificateEntry {
    fn as_bytes(&self) -> Vec<u8> {
        let mut ret : Vec<u8> = vec![];

        // IMPORTANT: This length here is a u24 in the standard, NOT a u32
        ret.write_u32::<NetworkEndian>(self.cert_data.len() as u32).unwrap();
        ret.drain(..1);
        ret.extend(&self.cert_data);
        ret.extend(u16_vector_as_bytes(&self.extensions).iter());
        ret
    }
}

impl TLSToBytes for KeyUpdateRequest {
    fn as_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

impl TLSToBytes for SignatureScheme {
    fn as_bytes(&self) -> Vec<u8> {
        let mut ret : Vec<u8> = vec![];
        ret.write_u16::<NetworkEndian>(*self as u16).unwrap();
        ret
    }
}

impl TLSToBytes for Extension {
    fn as_bytes(&self) -> Vec<u8> {
        let mut ret : Vec<u8> = vec![];
        let mut buf : Vec<u8> = vec![];

        // Write extension data length

        // Currently, the only extension the server sends is KeyShare
        match *self {
            Extension::KeyShare(KeyShare::ServerHello(ref inner)) => {
                buf.write_u16::<NetworkEndian>(inner.group as u16).unwrap();
                buf.write_u16::<NetworkEndian>(inner.key_exchange.len() as u16).unwrap();
                buf.extend(&inner.key_exchange);

                ret.write_u16::<NetworkEndian>(40).unwrap();
                ret.write_u16::<NetworkEndian>(buf.len() as u16).unwrap();
                ret.extend(buf.iter());
            }
            _ => {}
        };

        ret
    }
}

impl TLSToBytes for HandshakeMessage {
	fn as_bytes(&self) -> Vec<u8> {

        let mut ret : Vec<u8> = vec![];

	    match *self {
			HandshakeMessage::InvalidMessage => (),
			HandshakeMessage::ClientHello(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.legacy_version).unwrap();
                ret.extend(inner.random.iter());
                ret.extend(u8_bytevec_as_bytes(&inner.legacy_session_id).iter());
                ret.extend(u16_vector_as_bytes(&inner.cipher_suites).iter());
                ret.extend(u8_bytevec_as_bytes(&inner.legacy_compression_methods).iter());
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
			HandshakeMessage::ServerHello(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.version).unwrap();
                ret.extend(inner.random.iter());
                ret.extend(inner.cipher_suite.as_bytes().iter());
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
            // This is correct, it is supposed to be empty
			HandshakeMessage::EndOfEarlyData(_) => (),
			HandshakeMessage::HelloRetryRequest(ref inner) => {
                ret.write_u16::<NetworkEndian>(inner.server_version).unwrap();
                ret.extend(inner.cipher_suite.as_bytes().iter());
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
			HandshakeMessage::EncryptedExtensions(ref inner) => {
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
			HandshakeMessage::CertificateRequest(ref inner) => {
                ret.extend(u8_bytevec_as_bytes(&inner.certificate_request_context).iter());
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
			HandshakeMessage::Certificate(ref inner) => {
                ret.extend(u8_bytevec_as_bytes(&inner.certificate_request_context).iter());
                ret.extend(u16_vector_as_bytes(&inner.certificate_list).iter());
            },
			HandshakeMessage::CertificateVerify(ref inner) => {
                ret.extend(inner.algorithm.as_bytes().iter());
                ret.extend(u16_bytevec_as_bytes(&inner.signature).iter());
            },
			HandshakeMessage::Finished(ref inner) => {
                ret.extend(u16_bytevec_as_bytes(&inner.verify_data).iter());
            },
			HandshakeMessage::NewSessionTicket(ref inner) => {
                ret.write_u32::<NetworkEndian>(inner.ticket_lifetime).unwrap();
                ret.write_u32::<NetworkEndian>(inner.ticket_age_add).unwrap();
                ret.extend(u16_bytevec_as_bytes(&inner.ticket).iter());
                ret.extend(u16_vector_as_bytes(&inner.extensions).iter());
            },
			HandshakeMessage::KeyUpdate(ref inner) => {
                ret.extend(inner.request_update.as_bytes().iter());
            },
	    };

        ret
	}
}
