#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

// these lints throw lots of warnings
// in the external bindings, so allow for now
// to make the log more readable
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// some non-clippy lints borrowed from
// https://pascalhertleif.de/artikel/good-practices-for-writing-rust-libraries/
#![warn(missing_docs,
        missing_debug_implementations,
        missing_copy_implementations,
        trivial_numeric_casts,
//        trivial_casts,
        unstable_features,
        unused_import_braces,
        unused_qualifications)]

extern crate pem;

mod structures;
mod serialization;
mod extensions;
mod crypto;
mod alert;

use std::mem;
use std::io::Read;
use std::io::Write;
use pem::{Pem, parse_many};
use std::fs::File;
use serialization::TLSToBytes;
extern crate byteorder;

use self::byteorder::{NetworkEndian, WriteBytesExt};
use structures::{Random, ClientHello, CipherSuite, Extension, ContentType,
                    HandshakeMessage, ServerHello, TLSPlaintext, TLSState, TLSError,
                    ExtensionType, NamedGroup, KeyShare, KeyShareEntry,
                    EncryptedExtensions, CertificateEntry, Certificate,
                    CertificateVerify, SignatureScheme, Finished,
                    TLSCiphertext, TLSInnerPlaintext, HandshakeType,
                    HandshakeBytes, Alert, AlertLevel, AlertDescription};

extern crate openssl;
use self::openssl::ec::EcKey;
use self::openssl::pkey::PKey;

// Misc. functions
fn bytes_to_u16(bytes : &[u8]) -> u16 {
	((bytes[0] as u16) << 8) | (bytes[1] as u16)
}

pub struct TLS_config {
    certificates : Vec<Pem>,
    private_key : PKey
}

pub fn tls_configure(cert_path: &str, key_path: &str) -> Result<TLS_config, TLSError> {
    // Read certificate chain
    let mut certfile = try!(File::open(cert_path).or(Err(TLSError::InvalidCertificatePath)));

    let mut filebuf = String::new();
    try!(certfile.read_to_string(&mut filebuf).or(Err(TLSError::InvalidCertificate)));
    let certificates = parse_many(&filebuf);

    // Read private key
    let mut keyfile = try!(File::open(key_path).or(Err(TLSError::InvalidPrivateKeyPath)));

    let mut filebuf = String::new();
    try!(keyfile.read_to_string(&mut filebuf).or(Err(TLSError::InvalidPrivateKey)));

    // Generate PKey object
    let eckey = try!(EcKey::private_key_from_pem(filebuf.as_bytes()).or(Err(TLSError::InvalidPrivateKeyFile)));
    let private_key = try!(PKey::from_ec_key(eckey).or(Err(TLSError::InvalidPrivateKeyFile)));

    Ok(TLS_config{certificates: certificates, private_key: private_key})
}

// Each connection needs to have its own TLS_session object
pub struct TLS_session<'a> {
	reader : &'a mut Read,
	writer : &'a mut Write,

	state : TLSState,

	// Boolean if we have sent a HelloRetryRequest
	sent_hello_retry : bool,

    // ECDHE x25519 shared key
    shared_key : Vec<u8>,

    // Handshake traffic secret
    handshake_secret : Vec<u8>,
    server_hts : Vec<u8>,
    client_hts : Vec<u8>,

    // Application traffic secret
    server_traffic_secret : Vec<u8>,
    client_traffic_secret : Vec<u8>,

    // Current AEAD key, iv, and nonce
    aead_write_key : Vec<u8>,
    aead_write_iv : Vec<u8>,
    aead_write_nonce : Vec<u8>,
    aead_read_key : Vec<u8>,
    aead_read_iv : Vec<u8>,
    aead_read_nonce : Vec<u8>,

    // Sequence number
    read_sequence_number : u64,
    write_sequence_number : u64,

	// Cache any remaining bytes in a TLS record
    ctypecache : ContentType,
	recordcache: Vec<u8>,

    // Transcript Hash state
    th_state : crypto::crypto_hash_sha256_state,
}

pub fn tls_init<'a, R : Read, W : Write>(read : &'a mut R, write : &'a mut W) -> Result<TLS_session<'a>, TLSError> {

    // Call sodium_init here. According to the documentation, we can call it multiple times w/o
    // causing any errors
    if unsafe { crypto::sodium_init() } == -1 {
        return Err(TLSError::CryptoInitError);
    }

    let mut ret = TLS_session{reader : read, writer : write, state : TLSState::Start,
        sent_hello_retry : false, shared_key : vec![], server_traffic_secret : vec![],
        ctypecache : ContentType::InvalidReserved, recordcache : vec![],
        th_state : unsafe { mem::uninitialized() }, server_hts : vec![],
        client_hts : vec![], client_traffic_secret : vec![], handshake_secret : vec![],
        aead_write_key : vec![], aead_write_iv : vec![], aead_write_nonce : vec![],
        read_sequence_number : 0, aead_read_key : vec![], aead_read_iv : vec![], aead_read_nonce : vec![],
        write_sequence_number : 0
    };

    // Initialize our transcript hash state
    let stateptr = &mut ret.th_state as *mut crypto::crypto_hash_sha256_state;
    unsafe { crypto::crypto_hash_sha256_init(stateptr) };

	Ok(ret)
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<'a> TLS_session<'a> {
    /*
        Read implements reading directly from the TLSPlaintext streams.
        It will handle retrieving a new TLSPlaintext in the case of fragmentation
    */
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, TLSError> {
        if dest.len() > self.recordcache.len() {
            try!(self.fill_recordcache());
        }

        let len = dest.len();
        dest.clone_from_slice(self.recordcache.drain(0..len).collect::<Vec<u8>>().as_slice());

        Ok(len)
    }

    fn write(&mut self, src: &[u8], ctype: ContentType) -> Result<usize, TLSError> {
        let plaintext = try!(self.create_tlsplaintext(ctype, src.to_vec()));
        try!(self.send_tlsplaintext(plaintext));
        Ok(src.len())
    }

    fn write_encrypted(&mut self, src: &[u8]) -> Result<usize, TLSError> {
        let ciphertext = try!(self.create_tlsciphertext(ContentType::ApplicationData, src.to_vec()));
        try!(self.send_tlsciphertext(ciphertext));
        Ok(src.len())
    }

    fn read_encrypted(&mut self, dest: &mut [u8]) -> Result<usize, TLSError> {
        if dest.len() > self.recordcache.len() {
            try!(self.fill_recordcache_encrypted());
        }

        let len = dest.len();
        dest.clone_from_slice(self.recordcache.drain(0..len).collect::<Vec<u8>>().as_slice());
        Ok(len)
    }

    fn read_u8(&mut self) -> Result<u8, TLSError> {
        if self.recordcache.len() < 1 {
            // Grab another fragment
            try!(self.fill_recordcache());
        }

        Ok(self.recordcache.remove(0))
    }

    fn read_u8_encrypted(&mut self) -> Result<u8, TLSError> {
        if self.recordcache.len() < 1 {
            // Grab another fragment
            try!(self.fill_recordcache_encrypted());
        }

        Ok(self.recordcache.remove(0))
    }

    fn read_u16(&mut self) -> Result<u16, TLSError> {
        if self.recordcache.len() < 2 {
            // Grab another fragment
            try!(self.fill_recordcache());
        }

        let first = self.recordcache.remove(0);
        let second = self.recordcache.remove(0);
        Ok(((first as u16) << 8) | (second as u16))
    }

    fn read_u16_encrypted(&mut self) -> Result<u16, TLSError> {
        if self.recordcache.len() < 2 {
            // Grab another fragment
            try!(self.fill_recordcache_encrypted());
        }

        let first = self.recordcache.remove(0);
        let second = self.recordcache.remove(0);
        Ok(((first as u16) << 8) | (second as u16))
    }

    fn send_alert(&mut self, alertdesc : AlertDescription) {
        let cn = Alert { level : AlertLevel::Fatal, description : alertdesc };
        let data = cn.as_bytes();

        // We explicitly don't care about the result here. If the alert fails,
        // we are closing the connection anyways so it doesn't matter
        let _ = match self.state {
            TLSState::Start | TLSState::RecievedClientHello => self.write(&data, ContentType::Alert),
            TLSState::Error | TLSState::Closed => Ok(0),
            _ => self.write_encrypted(&data),
        };
    }

    fn close_connection(&mut self) {
        self.state = TLSState::Closed;

        // FIXME: Secrets need to be removed from memory
    }

    fn handle_alert(&mut self, desc: AlertDescription) -> TLSError {
        // If we have a Closure Alert, we have to notify the client
        match desc {
            AlertDescription::CloseNotify | AlertDescription::UserCanceled => {
               self.send_alert(AlertDescription::CloseNotify);
            },
            _ => {}
        }

        // Close the connection
        self.close_connection();

        TLSError::ConnectionClosed
    }

    fn drain_recordcache(&mut self) {
        self.recordcache.clear()
    }

    fn fill_recordcache(&mut self) -> Result<(), TLSError> {
        // Grab another fragment
        let tlsplaintext : TLSPlaintext = try!(self.get_next_tlsplaintext());
        self.ctypecache = tlsplaintext.ctype;

        // Check for an Alert message
        if self.ctypecache == ContentType::Alert {
            // TLS 1.3 mandates we ignore the AlertLevel
            let alert : AlertDescription = alert::parse_alertdesc(tlsplaintext.fragment[1]);
            return Err(self.handle_alert(alert));
        }

        self.recordcache.extend(tlsplaintext.fragment.iter());
        Ok(())
    }

    fn fill_recordcache_encrypted(&mut self) -> Result<(), TLSError> {
        // Grab another fragment
        let tlsciphertext : TLSCiphertext = try!(self.get_next_tlsciphertext());

        // Decrypt the data
        let mut decrypted = try!(crypto::aead_decrypt(&self.aead_read_key, &self.aead_read_nonce, &tlsciphertext.encrypted_record));

        // Remove padding
        let end = match (0..decrypted.len()).rev().find(|&x| decrypted[x] != 0x00) {
            Some(x) => x,
            None => return Err(TLSError::InvalidMessagePadding)
        };

        // Set our content type
        self.ctypecache = match decrypted[end] {
            20 => ContentType::ChangeCipherSpecReserved,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _  => return Err(TLSError::InvalidMessage)
        };

        // Chop one off for the content type
        self.recordcache.extend(decrypted.drain(0..(end)));

        // Check for an Alert message
        if self.ctypecache == ContentType::Alert {
            // TLS 1.3 mandates we ignore the AlertLevel
            decrypted.remove(0);
            let alert : AlertDescription = alert::parse_alertdesc(decrypted.remove(0));
            return Err(self.handle_alert(alert));
        }

        // Increment sequence number
        self.read_sequence_number += 1;
        self.aead_read_nonce = try!(crypto::generate_nonce(self.read_sequence_number, &self.aead_read_iv));

        Ok(())
    }

    fn create_tlsplaintext(&mut self, contenttype: ContentType, data: Vec<u8>) -> Result<TLSPlaintext, TLSError> {
        Ok(TLSPlaintext{ctype : contenttype, legacy_record_version : 0x0301, length : data.len() as u16, fragment : data})
    }

    fn create_tlsciphertext(&mut self, contenttype: ContentType, data: Vec<u8>) -> Result<TLSCiphertext, TLSError> {
        let innerplaintext = TLSInnerPlaintext{content : data, ctype : contenttype, zeros : vec![]};

        // Encrypt with our chosen AEAD
        let encrypted_record = try!(crypto::aead_encrypt(&self.aead_write_key, &self.aead_write_nonce, &innerplaintext.as_bytes()));

        Ok(TLSCiphertext{opaque_type : ContentType::ApplicationData, legacy_record_version : 0x0301, length : encrypted_record.len() as u16, encrypted_record : encrypted_record})
    }

    fn send_tlsplaintext(&mut self, tlsplaintext : TLSPlaintext) -> Result<(), TLSError> {
    	let data : Vec<u8> = (&tlsplaintext).as_bytes();

    	try!(self.writer.write_all(&data).or(Err(TLSError::ReadError)));
        self.writer.flush().or(Err(TLSError::ReadError))
    }

    fn send_tlsciphertext(&mut self, tlsciphertext : TLSCiphertext) -> Result<(), TLSError> {
    	let data : Vec<u8> = (&tlsciphertext).as_bytes();

        // Increment sequence number
        self.write_sequence_number += 1;
        self.aead_write_nonce = try!(crypto::generate_nonce(self.write_sequence_number, &self.aead_write_iv));

    	try!(self.writer.write_all(data.as_slice()).or(Err(TLSError::ReadError)));
        self.writer.flush().or(Err(TLSError::ReadError))
    }

    fn get_next_tlsciphertext(&mut self) -> Result<TLSCiphertext, TLSError> {

		// Try to read TLSCiphertext header
		let mut buffer : [u8; 5] = [0; 5];
		try!(self.reader.read_exact(&mut buffer).or(Err(TLSError::ReadError)));

		// Match content type (is there a better way to do this in Rust stable?)
		let contenttype : ContentType = match buffer[0] {
			23 => ContentType::ApplicationData,
            21 => {
                // Process the alert message
                let alert : AlertDescription = alert::parse_alertdesc(buffer[2]);
                return Err(self.handle_alert(alert));
            }
			_  => return Err(TLSError::InvalidCiphertextHeader)
		};

		// Match legacy protocol version
		let legacy_version = bytes_to_u16(&buffer[1..3]);
		if legacy_version != 0x0301 {
			return Err(TLSError::InvalidCiphertextHeader)
		}

		// Make sure length is less than 2^14-1
		let length = bytes_to_u16(&buffer[3..5]);
		if length >= 16384 {
			return Err(TLSError::InvalidMessageLength)
		}

		// Read the remaining data from the buffer
		let mut encrypted_record = vec![0; length as usize];
		try!(self.reader.read_exact(encrypted_record.as_mut_slice()).or(Err(TLSError::ReadError)));

        Ok(TLSCiphertext{opaque_type : contenttype, legacy_record_version : legacy_version, length : length, encrypted_record : encrypted_record})
	}

	fn get_next_tlsplaintext(&mut self) -> Result<TLSPlaintext, TLSError> {
		// Try to read TLSPlaintext header
		let mut buffer : [u8; 5] = [0; 5];
		try!(self.reader.read_exact(&mut buffer).or(Err(TLSError::ReadError)));

		// Match content type (is there a better way to do this in Rust stable?)
		let contenttype : ContentType = match buffer[0] {
			0  => ContentType::InvalidReserved,
			20 => ContentType::ChangeCipherSpecReserved,
			21 => ContentType::Alert,
			22 => ContentType::Handshake,
			23 => ContentType::ApplicationData,
			_  => return Err(TLSError::InvalidMessage)
		};

		// Match legacy protocol version
		let legacy_version = bytes_to_u16(&buffer[1..3]);
		if legacy_version != 0x0301 {
			return Err(TLSError::InvalidHandshakeVersionError)
		}

		// Make sure length is less than 2^14-1
		let length = bytes_to_u16(&buffer[3..5]);
		if length >= 16384 {
			return Err(TLSError::InvalidMessageLength)
		}

		// Read the remaining data from the buffer
		let mut data = vec![0; length as usize];
		try!(self.reader.read_exact(data.as_mut_slice()).or(Err(TLSError::ReadError)));

		Ok(TLSPlaintext{ctype: contenttype, legacy_record_version: legacy_version, length: length, fragment: data})
	}

	fn process_ciphersuites(&mut self, data : &[u8]) -> Result<Vec<CipherSuite>, TLSError> {
        let mut ret : Vec<CipherSuite> = Vec::new();
        let mut iter = data.iter();

        loop {
            let first = iter.next();
            if first.is_none() {
                break
            }
            let first = first.unwrap();
            let second = iter.next().unwrap();
            ret.push(match ((*first as u16) << 8) | (*second as u16) {
                0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
                0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
                0x1303 => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                0x1304 => CipherSuite::TLS_AES_128_CCM_SHA256,
                0x1305 => CipherSuite::TLS_AES_128_CCM_8_SHA256,
                0x00ff => CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                _ => return Err(TLSError::InvalidCipherSuite)
            });
        }
	    Ok(ret)
    }

	fn process_extensions(&mut self, data : &[u8]) -> Result<Vec<Extension>, TLSError> {

        let mut ret : Vec<Extension> = Vec::new();
        let mut iter = data.iter();

        while let Some(first) = iter.next() {
            let second = iter.next().unwrap();

            let extension_type = ((*first as u16) << 8) | (*second as u16);

            // FIXME: Use this
            let a = iter.next().unwrap(); let b = iter.next().unwrap();
            let extension_length = (*a as u16) | (*b as u16);

            let result : Option<Extension> = match extension_type {
    			10 => Some(try!(Extension::parse_supported_groups(&mut iter))),
    			13 => Some(try!(Extension::parse_signature_algorithms(&mut iter))),
    			40 => Some(try!(Extension::parse_keyshare(&mut iter))),
    			41 => Some(try!(Extension::parse_preshared_key(&mut iter))),
    			42 => Some(try!(Extension::parse_earlydata(&mut iter))),
    			43 => Some(try!(Extension::parse_supported_versions(&mut iter))),
    			44 => Some(try!(Extension::parse_cookie(&mut iter))),
    			45 => Some(try!(Extension::parse_psk_key_exchange_modes(&mut iter))),

                /* We don't implement the "certificate_authories" extension */
    			47 => None,
    			48 => Some(try!(Extension::parse_oldfilters(&mut iter))),
                _ => {
                    /* We must ignore unknown extensions, so just read the bytes */
                    for _ in 0..extension_length {
                        iter.next();
                    }
                    None
                }
            };

            if let Some(x) = result {
                ret.push(x);
            }
        }

		Ok(ret)
	}

    fn read_finished(&mut self) -> Result<Finished, TLSError> {
        // Fill our cache before we start reading
        self.drain_recordcache();
        try!(self.fill_recordcache_encrypted());

        // Make sure we are dealing with a Handshake TLSPlaintext
        if self.ctypecache != ContentType::Handshake {
            return Err(TLSError::InvalidMessage)
        }

        // Make sure this is a Finished message
        let msg_type : u8 = try!(self.read_u8_encrypted());
        if msg_type != 20 {
            return Err(TLSError::InvalidMessage)
        }

        // Grab our overall message length here
        let mut len : Vec<u8> = vec![0; 3];
        try!(self.read_encrypted(len.as_mut_slice()));

        let length : u32 = ((len[0] as u32) << 16) | ((len[1] as u32) << 8) | (len[2] as u32);

        // Read in the entire TLSInnerPlaintext
        let mut verify_data : Vec<u8> = vec![0; length as usize];
        try!(self.read_encrypted(verify_data.as_mut_slice()));

        Ok(Finished { verify_data : verify_data })
    }

	fn read_clienthello(&mut self) -> Result<ClientHello, TLSError> {
        // Fill our cache before we start reading
        self.drain_recordcache();
        try!(self.fill_recordcache());

        // Make sure we are dealing with a Handshake TLSPlaintext
        if self.ctypecache != ContentType::Handshake {
            return Err(TLSError::InvalidMessage)
        }

        // Make sure this is a ClientHello message
        let msg_type : u8 = try!(self.read_u8());
        if msg_type != 0x1 {
            return Err(TLSError::InvalidMessage)
        }

        // Grab our overall message length here
        // FIXME: Use this to prebuffer the whole ClientHello
        let mut len : Vec<u8> = vec![0; 3];
        try!(self.read(len.as_mut_slice()));

        // Grab our legacy version
        let legacy_version: u16 = try!(self.read_u16());
        if legacy_version != 0x0303 {
            return Err(TLSError::InvalidHandshakeVersionError)
        }

        // The client random must be exactly 32 bytes
        let mut random : Random = [0; 32];
        try!(self.read(&mut random));

        // Legacy session ID can be 0-32 bytes
        let lsi_length : usize = try!(self.read_u8()) as usize;
        if lsi_length > 32 {
            return Err(TLSError::InvalidMessageLength)
        }

        let mut legacy_session_id = vec![0; lsi_length];
        try!(self.read(legacy_session_id.as_mut_slice()));

        // Read in the list of valid cipher suites
        // In reality, for TLS 1.3, there are only 5 valid cipher suites, so this list
        // should never have more than 5 elements (10 bytes) in it.
        let cslist_length : usize = try!(self.read_u16()) as usize;
        let max_cslist_length: usize = ((2 as u32).pow(16) - 2) as usize;
        if cslist_length < 2 || cslist_length > max_cslist_length || cslist_length % 2 != 0 {
            return Err(TLSError::InvalidMessageLength)
        }

        // Process the list of ciphersuites -- in particular, minimal-TLS doesn't support the full list
        let mut cipher_suites : Vec<u8> = vec![0; cslist_length];
        try!(self.read(cipher_suites.as_mut_slice()));

        // Read in legacy compression methods (should just be null compression)
        let comp_length = try!(self.read_u8()) as usize;
        if comp_length != 1 {
            return Err(TLSError::InvalidMessageLength)
        }

        // 0x00 is null compression
        if try!(self.read_u8()) != 0x00 {
            return Err(TLSError::InvalidHandshakeCompression)
        }

        // Parse ClientHello extensions
        let ext_length = try!(self.read_u16()) as usize;
        let max_ext_length:usize  = ( (2 as u32).pow(16) -1 ) as usize;
        if ext_length < 8 || ext_length > max_ext_length {
            return Err(TLSError::InvalidMessageLength)
        }

        let mut extensions : Vec<u8> = vec![0; ext_length];
        // FIXME: If there is a pre_shared_key extension, it must be the last
        // extension in the ClientHello
        try!(self.read(extensions.as_mut_slice()));

        // FIXME: This is a code smell. We should have a central place for parsing
        // Any sort of HandshakeMessage

        // Since we might not support all the extensions, we should just add them all to the hash now
        let mut buffer = vec![];
        buffer.write_u16::<NetworkEndian>(legacy_version).unwrap();
        buffer.extend(random.iter());
        buffer.extend(serialization::u8_bytevec_as_bytes(&legacy_session_id));
        buffer.extend(serialization::u16_bytevec_as_bytes(&cipher_suites));
        buffer.extend(serialization::u8_bytevec_as_bytes(&[0]));
        buffer.extend(serialization::u16_bytevec_as_bytes(&extensions));
        let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
        let buffer = HandshakeBytes { msg_type : HandshakeType::ClientHello, length : 0, body : buffer }.as_bytes();
        unsafe { crypto::crypto_hash_sha256_update(stateptr, buffer.as_ptr(), buffer.len() as u64) };

        let ret = ClientHello{
            legacy_version: legacy_version,
            random: random,
            legacy_session_id: legacy_session_id,
            cipher_suites: try!(self.process_ciphersuites(cipher_suites.as_slice())),
            legacy_compression_methods: vec![0],
            extensions: try!(self.process_extensions(extensions.as_slice()))
        };

        // Add the clienthello to the transcript hash queue

        Ok(ret)
	}

	fn negotiate_ciphersuite(&mut self, ciphersuites : &[CipherSuite]) -> Result<CipherSuite, TLSError> {
		// We only support one ciphersuite - TLS_CHACHA20_POLY1305_SHA256

		if !ciphersuites.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
			return Err(TLSError::UnsupportedCipherSuite)
		}

		Ok(CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
	}

    // FIXME: Must not be any recognized extensions that are not valid for a ClientHello
    // FIXME: Check for SNI extension
	fn validate_extensions(&mut self, clienthello : &ClientHello) -> Result<Vec<Extension>, TLSError> {

        // FIXME: Check to make sure there are no duplicate extensions
        let mut processed = vec![];

        // List of extensions we'll return
        let mut ret : Vec<Extension> = vec![];

        // Check to make sure there is a "supported_versions" extension with TLSv1.3
        for ext in &clienthello.extensions {
            match *ext {
                Extension::SupportedVersions(ref sv) => {
                    if processed.contains(&ExtensionType::SupportedVersions) {
                        return Err(TLSError::DuplicateExtensions);
                    }

                    // Make sure the client supports TLS 1.3 draft 19
                    if !sv.versions.contains(&0x7f14) {
                        return Err(TLSError::InvalidTLSSupportedVersion);
                    }

                    processed.push(ExtensionType::SupportedVersions);
                },
                Extension::SignatureAlgorithms(ref ssl) => {
                   /*
                        Technically, we are supposed to parse out the list of supported
                        certificates by the client and verify that our server certificate
                        supports signing by that algorithm. However, according to the TLS
                        RFC 4.4.2.2, we SHOULD continue the handshake even if our certificate
                        supports signing with a different algorithm.

                        tl;dr: we don't care what this extension says
                    */
                    if processed.contains(&ExtensionType::SignatureAlgorithms) {
                        return Err(TLSError::DuplicateExtensions);
                    }
                    processed.push(ExtensionType::SignatureAlgorithms);
                },
                Extension::KeyShare(ref kso) => {
                    // FIXME: Client MAY send an empty client_shares list to request
                    // the server choose the group and send it in the next round-trip

                    if processed.contains(&ExtensionType::KeyShare) {
                        return Err(TLSError::DuplicateExtensions);
                    }

                    if let KeyShare::ClientHello(ref ks) = *kso {
                        // We only support x25519, so make sure this is in the list
                        match (*ks).iter().find(|&x| x.group == NamedGroup::x25519) {
                            Some(x) => {
                                // Compute our x25519 shared key
                                let (shared_key, server_pub) = try!(crypto::x25519_key_exchange(&x.key_exchange));
                                self.shared_key = shared_key;

                                // Add an extension indicating our response
                                ret.push(Extension::KeyShare(KeyShare::ServerHello(KeyShareEntry{
                                    group: x.group,
                                    key_exchange : server_pub
                                })));
                            },
                            None => {
                                // FIXME: We should return a HelloRetryRequest here with x25519
                                return Err(TLSError::InvalidKeyShare);
                            }
                        }

                        processed.push(ExtensionType::KeyShare);
                    } else {
                        return Err(TLSError::InvalidKeyShare);
                    }
                },
                // KeyShareEntry client_shares<0..2^16-1>
                // FIXME: Add support for PSK/session resumption
                _ => {}
            };
        }

        /*
            We require certain extensions, so make sure we have:
            - supported_versions
            - signature_algorithms
            - key_share
        */
        if !processed.contains(&ExtensionType::KeyShare) {
            return Err(TLSError::MissingExtension);
        }

        if !processed.contains(&ExtensionType::SignatureAlgorithms) {
            return Err(TLSError::MissingExtension);
        }

        if !processed.contains(&ExtensionType::SupportedVersions) {
            return Err(TLSError::MissingExtension);
        }

		Ok(ret)
	}

	fn negotiate_serverhello(&mut self, clienthello: &ClientHello) -> Result<HandshakeMessage, TLSError> {
        // Validate the client legacy version
        if clienthello.legacy_version != 0x0303 {
            return Err(TLSError::InvalidHandshakeVersionError)
        }

        // Choose a cipher suite
        let ciphersuite = try!(self.negotiate_ciphersuite(&clienthello.cipher_suites));

        // Make sure we only have null compression sent
        if clienthello.legacy_compression_methods.len() != 1 ||
            clienthello.legacy_compression_methods[0] != 0x00 {
                return Err(TLSError::InvalidHandshakeCompression)
        }

        // Go through extensions and figure out which replies we need to send
        // FIXME: It's possible that we decide to return a HelloRetryRequest here,
        // so we should handle that
        let extensions : Vec<Extension> = try!(self.validate_extensions(clienthello));

        Ok(HandshakeMessage::ServerHello(ServerHello{
            version : 0x07f14, random: try!(crypto::gen_server_random()),
            cipher_suite: ciphersuite, extensions : extensions}))
	}

	fn send_message(&mut self, messagequeue : Vec<HandshakeMessage>) -> Result<(), TLSError> {
		if !messagequeue.is_empty() {
			let mut data : Vec<u8> = Vec::new();

			// Loop over all messages and serialize them
			for x in &messagequeue {

                let msg_type = match *x {
                    HandshakeMessage::ClientHello(_) => 1,
                    HandshakeMessage::ServerHello(_) => 2,
                    HandshakeMessage::HelloRetryRequest(_) => 5,
                    _ => return Err(TLSError::InvalidMessage)
                };

				let ret = x.as_bytes();

                let msg_len = ret.len();
                if msg_len > 16777215 {
                    return Err(TLSError::InvalidMessageLength);
                }

				if data.len() + ret.len() > (16384 - 4) {
					// Flush the existing messages, then continue
					let tlsplaintext = try!(self.create_tlsplaintext(ContentType::Handshake, data.drain(..).collect()));
					try!(self.send_tlsplaintext(tlsplaintext));
				}
                data.push(msg_type);
                data.push(((msg_len & 0x00ff0000) >> 16) as u8);
                data.push(((msg_len & 0x0000ff00) >> 8) as u8);
                data.push((msg_len & 0x000000ff) as u8);
				data.extend(ret.iter())
			}

			// Flush any remaining messages
			let tlsplaintext = try!(self.create_tlsplaintext(ContentType::Handshake, data));
			try!(self.send_tlsplaintext(tlsplaintext));
		}
		Ok(())
	}

    fn send_encrypted_message(&mut self, encryptedqueue : Vec<HandshakeMessage>) -> Result<(), TLSError> {
		if !encryptedqueue.is_empty() {
			let mut data : Vec<u8> = Vec::new();

			// Loop over all messages and serialize them
			for x in &encryptedqueue {

                let msg_type = match *x {
                    HandshakeMessage::EncryptedExtensions(_) => 8,
                    HandshakeMessage::Certificate(_) => 11,
                    HandshakeMessage::CertificateRequest(_) => 13,
                    HandshakeMessage::CertificateVerify(_) => 15,
                    HandshakeMessage::Finished(_) => 20,
                    _ => return Err(TLSError::InvalidMessage)
                };

				let ret = x.as_bytes();

                let msg_len = ret.len();
                if msg_len > 16777215 {
                    return Err(TLSError::InvalidMessageLength);
                }

                // FIXME: Count the new message header length in this
				if data.len() + ret.len() > 16384 {

					// Flush the existing messages, then continue
					let tlsciphertext = try!(self.create_tlsciphertext(ContentType::Handshake, data.drain(..).collect()));
					try!(self.send_tlsciphertext(tlsciphertext));
				}

                data.push(msg_type as u8);
                data.push(((msg_len & 0x00ff0000) >> 16) as u8);
                data.push(((msg_len & 0x0000ff00) >> 8) as u8);
                data.push((msg_len & 0x000000ff) as u8);
				data.extend(ret.iter())
			}

			// Flush any remaining messages
			let tlsciphertext = try!(self.create_tlsciphertext(ContentType::Handshake, data));
			try!(self.send_tlsciphertext(tlsciphertext));
		}
		Ok(())
	}

	fn transition(&mut self, hs_message : HandshakeMessage, config : &TLS_config) -> Result<HandshakeMessage, TLSError> {

		// This queue represents any server messages we need to drain after calling transition
		let mut messagequeue : Vec<HandshakeMessage> = vec![];

        // This queue is the same as the above, but for messages that need to be encrypted
        let mut encryptedqueue : Vec<HandshakeMessage> = vec![];

		let result = match self.state {
			TLSState::Start => {
				// Try to recieve the ClientHello
				let hs_message = HandshakeMessage::ClientHello(try!(self.read_clienthello()));

                // Update transcript hash state
                /* let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;

                let hs_msg = HandshakeBytes { msg_type : HandshakeType::ClientHello, length : 0, body : hs_message.as_bytes() };
                let ret = hs_msg.as_bytes();

                unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) }; */

				// We can transition to the next state
				self.state = TLSState::RecievedClientHello;
				Ok(hs_message)
			},
			TLSState::RecievedClientHello => {
				// We need to evaluate the ClientHello to determine if we want to keep it
                let hs_message = if let HandshakeMessage::ClientHello(clienthello) = hs_message {
                    try!(self.negotiate_serverhello(&clienthello))
                } else {
                    return Err(TLSError::InvalidMessage)
                };

				// Check if this is a ServerHello or a HelloRetryRequest
				match hs_message {
					HandshakeMessage::ServerHello(_) => {

                        // Add the message to our transcript hash state
                        let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
                        let hs_msg = HandshakeBytes { msg_type : HandshakeType::ServerHello, length : 0, body : hs_message.as_bytes() };
                        let ret = hs_msg.as_bytes();
                        unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) };

						// We don't need to do anything else except transition state
						self.state = TLSState::Negotiated;
						Ok(hs_message)
					},
					HandshakeMessage::HelloRetryRequest(_) => {
						if self.sent_hello_retry {
							/*
								We have already sent a HelloRetryRequest once, so
								abort to avoid DoS loop
							*/
							return Err(TLSError::InvalidMessage)
						}
						self.sent_hello_retry = true;

						// Queue the HelloRetryRequest to send back to the client
						messagequeue.push(hs_message);
						self.state = TLSState::Start;
						Ok(HandshakeMessage::InvalidMessage)
					},
					_ => return Err(TLSError::InvalidState)
				}
			},
			TLSState::Negotiated => {

                /*
                    We need to send the ServerHello, EncryptedExtensions,
                    Certificate, and CertificateVerify messages
                */

                // Queue ServerHello to be sent
                messagequeue.push(hs_message);

                // Generate derived secret (without PSK)
                let earlysecret = try!(crypto::generate_early_secret());

                let derivedsecret = try!(crypto::generate_derived_secret(&earlysecret));

                // Generate handshake keys
                self.handshake_secret = try!(crypto::generate_handshake_secret(&self.shared_key, &derivedsecret));

                let (server_hts, client_hts) = try!(crypto::generate_hts(&self.handshake_secret, &self.th_state));
                self.server_hts = server_hts;
                self.client_hts = client_hts;

                // Generate our handshake key and iv
                let (aead_key, aead_iv) = try!(crypto::generate_traffic_keyring(&self.server_hts));
                self.aead_write_key = aead_key;
                self.aead_write_iv = aead_iv;

                let (aead_key, aead_iv) = try!(crypto::generate_traffic_keyring(&self.client_hts));
                self.aead_read_key = aead_key;
                self.aead_read_iv = aead_iv;

                // Generate the initial nonce value
                self.aead_write_nonce = try!(crypto::generate_nonce(self.write_sequence_number, &self.aead_write_iv));
                self.aead_read_nonce = try!(crypto::generate_nonce(self.read_sequence_number, &self.aead_read_iv));

                // Send EncryptedExtensions
                let encrypted_extensions = HandshakeMessage::EncryptedExtensions(EncryptedExtensions{extensions: vec![]});

                let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
                let hs_msg = HandshakeBytes { msg_type : HandshakeType::EncryptedExtensions, length : 0, body : encrypted_extensions.as_bytes() };
                let ret = hs_msg.as_bytes();
                unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) };

                encryptedqueue.push(encrypted_extensions);

                // Send Certificate
                let cert_message_list = config.certificates.iter().map(|x| CertificateEntry{
                   cert_data : x.contents.clone(), extensions: vec![]
                }).collect();
                let cert_message = HandshakeMessage::Certificate(Certificate{certificate_request_context: vec![], certificate_list: cert_message_list});

                let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
                let hs_msg = HandshakeBytes { msg_type : HandshakeType::Certificate, length : 0, body : cert_message.as_bytes() };
                let ret = hs_msg.as_bytes();
                unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) };

                encryptedqueue.push(cert_message);

                // Send CertificateVerify
                let signature = try!(crypto::generate_cert_signature(&config.private_key, &self.th_state));
                let certverify_message = HandshakeMessage::CertificateVerify(
                CertificateVerify{
                    algorithm: SignatureScheme::ecdsa_secp256r1_sha256,
                    signature: signature
                });

                let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
                let hs_msg = HandshakeBytes { msg_type : HandshakeType::CertificateVerify, length : 0, body : certverify_message.as_bytes() };
                let ret = hs_msg.as_bytes();
                unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) };

                encryptedqueue.push(certverify_message);

                self.state = TLSState::WaitFlight2;
				Ok(HandshakeMessage::InvalidMessage)
			},

            /*
                This state is only used for 0-RTT communications, which we disable
                because they don't provide forward secrecy and can lead to replay attacks
            */
			TLSState::WaitEndOfEarlyData => {
				Err(TLSError::InvalidState)
			},

			TLSState::WaitFlight2 => {

                // Send Finished message
                let finished_message = HandshakeMessage::Finished(Finished{
                    verify_data : try!(crypto::generate_finished(&self.server_hts, &self.th_state))
                });

                let stateptr = &mut self.th_state as *mut crypto::crypto_hash_sha256_state;
                let hs_msg = HandshakeBytes { msg_type : HandshakeType::Finished, length : 0, body : finished_message.as_bytes() };
                let ret = hs_msg.as_bytes();
                unsafe { crypto::crypto_hash_sha256_update(stateptr, ret.as_ptr(), ret.len() as u64) };

                encryptedqueue.push(finished_message);

                // No 0-RTT, so nothing else to do here
                self.state = TLSState::WaitFinished;
				Ok(HandshakeMessage::InvalidMessage)
			},

            /*
                Because we don't support client certificates, we should
                never reach these states in our state machine
            */
			TLSState::WaitCert => {
				Err(TLSError::InvalidState)
			},
			TLSState::WaitCertificateVerify => {
				Err(TLSError::InvalidState)
			},


			TLSState::WaitFinished => {

                // Reset the sequence number and nonce value
                self.read_sequence_number = 0;
                self.write_sequence_number = 0;
                self.aead_write_nonce = try!(crypto::generate_nonce(self.write_sequence_number, &self.aead_write_iv));
                self.aead_read_nonce = try!(crypto::generate_nonce(self.read_sequence_number, &self.aead_read_iv));

                let finished_message = try!(self.read_finished());

                // Verify the message
                try!(crypto::verify_finished(&self.th_state, &self.client_hts, &finished_message.verify_data));

                // Generate application traffic secret
                let derivedsecret = try!(crypto::generate_derived_secret(&self.handshake_secret));
                let (server_traffic_secret, client_traffic_secret) = try!(crypto::generate_atf(&derivedsecret, &self.th_state));
                self.server_traffic_secret = server_traffic_secret;
                self.client_traffic_secret = client_traffic_secret;

                // Generate our traffic write key and iv
                let (aead_key, aead_iv) = try!(crypto::generate_traffic_keyring(&self.server_traffic_secret));
                self.aead_write_key = aead_key;
                self.aead_write_iv = aead_iv;

                let (aead_key, aead_iv) = try!(crypto::generate_traffic_keyring(&self.client_traffic_secret));
                self.aead_read_key = aead_key;
                self.aead_read_iv = aead_iv;

                // Reset the sequence number and nonce value
                self.read_sequence_number = 0;
                self.write_sequence_number = 0;
                self.aead_write_nonce = try!(crypto::generate_nonce(self.write_sequence_number, &self.aead_write_iv));
                self.aead_read_nonce = try!(crypto::generate_nonce(self.read_sequence_number, &self.aead_read_iv));

                // Record cache should be empty because we are changing keys
                if !self.recordcache.is_empty() {
                    return Err(TLSError::InvalidState)
                }

                // We're done! Advance to the connected state
                self.state = TLSState::Connected;
                Ok(HandshakeMessage::InvalidMessage)
			},
			TLSState::Connected => {
                // Nowhere else to go from here
                Ok(HandshakeMessage::InvalidMessage)
			},
            TLSState::Closed => {
                // The connection has been closed, so we shouldn't attempt to resume or continue it
                Ok(HandshakeMessage::InvalidMessage)
            },
            TLSState::Error => {
                // We encountered some error, and we shouldn't attempt to resume this connection
                Ok(HandshakeMessage::InvalidMessage)
            },
		};

		// Check if we need to send any messages
		try!(self.send_message(messagequeue));

        // Check if we need to send any encrypted messages
		try!(self.send_encrypted_message(encryptedqueue));

		result
	}

	pub fn tls_start(&mut self, config: &TLS_config) -> Result<(), TLSError> {

		// Ensure we are in the "start" state
		if self.state != TLSState::Start {
			return Err(TLSError::InvalidState)
		}

		/*
			We want to transition through the TLS state machine until we
			encounter an error, or complete the handshake
		*/
        let mut hs_message = HandshakeMessage::InvalidMessage;
		loop {
			match self.transition(hs_message, config) {
				Err(e) => {

                    // Send a TLS Alert
                    if let Some(x) = alert::error_to_alert(e) {
                        self.send_alert(x)
                    }

                    return Err(e)
                },
				Ok(x) => {
					if self.state == TLSState::Connected {
						break
					}
                    hs_message = x
				}
			}
		};

		// If all goes well, we should be in the "connected" state
		if self.state != TLSState::Connected {
			return Err(TLSError::InvalidState)
		}

		Ok(())
	}

    pub fn tls_receive(&mut self, dest: &mut [u8]) -> Result<usize, TLSError> {

        if self.state != TLSState::Connected {
            return Err(TLSError::InvalidState)
        }

        self.read_encrypted(dest)
    }

    pub fn tls_send(&mut self, src: &[u8]) -> Result<usize, TLSError> {

        if self.state != TLSState::Connected {
            return Err(TLSError::InvalidState)
        }

        self.write_encrypted(src)
    }

    pub fn tls_close(&mut self) {
        self.send_alert(AlertDescription::CloseNotify);
        self.close_connection();
    }
}
