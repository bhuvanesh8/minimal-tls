use std::slice::Iter;
use structures::{Extension, TLSError, ProtocolVersion, TLSState};
use structures::{Cookie, NamedGroup, NamedGroupList, SignatureScheme, SignatureSchemeList,
					SupportedVersions, PskKeyExchangeMode, PskKeyExchangeModes,
					PreSharedKeyExtension, KeyShare, KeyShareEntry, PskIdentity,
					PskBinderEntry, EarlyDataIndication, EarlyDataIndicationOptions, Empty};
use TLS_session;

impl Extension {

	pub fn parse_supported_groups<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);

        if length == 0 {
            return Err(TLSError::InvalidHandshakeError)
        }

		let mut ret : Vec<NamedGroup> = Vec::new();
		for _ in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(match ((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16) {
                0x0017 => NamedGroup::secp256r1,
                0x0018 => NamedGroup::secp384r1,
                0x0019 => NamedGroup::secp521r1,
                0x001d => NamedGroup::x25519,
                0x001e => NamedGroup::x448,
                0x0100 => NamedGroup::ffdhe2048,
                0x0101 => NamedGroup::ffdhe3072,
                0x0102 => NamedGroup::ffdhe4096,
                0x0103 => NamedGroup::ffdhe6144,
                0x0104 => NamedGroup::ffdhe8192,
                _ => return Err(TLSError::InvalidHandshakeError)
            });
		}

        Ok(Extension::SupportedGroups(NamedGroupList{named_group_list : ret}))
	}

	pub fn parse_signature_algorithms<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length == 0 || length as u32 > (2 as u32).pow(16) - 2{
            return Err(TLSError::InvalidHandshakeError)
        }

		let mut ret : Vec<SignatureScheme> = Vec::new();
		for _ in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(match ((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16) {
				/* RSASSA-PKCS1-v1_5 algorithms */
				0x0201 => SignatureScheme::rsa_pkcs1_sha1,
				0x0401 => SignatureScheme::rsa_pkcs1_sha256,
				0x0501 => SignatureScheme::rsa_pkcs1_sha384,
				0x0601 => SignatureScheme::rsa_pkcs1_sha512,

				/* ECDSA algorithms */
				0x0403 => SignatureScheme::ecdsa_secp256r1_sha256,
				0x0503 => SignatureScheme::ecdsa_secp384r1_sha384,
				0x0603 => SignatureScheme::ecdsa_secp521r1_sha512,

				/* RSASSA-PSS algorithms */
				0x0804 => SignatureScheme::rsa_pss_sha256,
				0x0805 => SignatureScheme::rsa_pss_sha384,
				0x0806 => SignatureScheme::rsa_pss_sha512,

				/* EdDSA algorithms */
				0x0807 => SignatureScheme::ed25519,
				0x0808 => SignatureScheme::ed448,
                _ => return Err(TLSError::InvalidHandshakeError)
            });
		}

        Ok(Extension::SignatureAlgorithms(SignatureSchemeList{supported_signature_algorithms : ret}))
	}

	fn parse_keyshare_entry<'a>(iter: &mut Iter<'a, u8>) -> Result<KeyShareEntry, TLSError> {
		// Parse NamedGroup
		let first = iter.next();
		let second = iter.next();
		if first.is_none() || second.is_none() {
			return Err(TLSError::InvalidHandshakeError)
		}

		let namedgroup : NamedGroup = match ((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16) {
			0x0017 => NamedGroup::secp256r1,
			0x0018 => NamedGroup::secp384r1,
			0x0019 => NamedGroup::secp521r1,
			0x001d => NamedGroup::x25519,
			0x001e => NamedGroup::x448,
			0x0100 => NamedGroup::ffdhe2048,
			0x0101 => NamedGroup::ffdhe3072,
			0x0102 => NamedGroup::ffdhe4096,
			0x0103 => NamedGroup::ffdhe6144,
			0x0104 => NamedGroup::ffdhe8192,
			_ => return Err(TLSError::InvalidHandshakeError)
        };

        // Read in key_exchange data
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 1 {
            return Err(TLSError::InvalidHandshakeError)
        }

        let ke_data : Vec<u8> = iter.take(length as usize).map(|&x| x).collect();

        Ok(KeyShareEntry{group: namedgroup, key_exchange: ke_data})
	}

	pub fn parse_keyshare<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		/*
			Technically, the format of this extension depends on whether we are parsing
			a ClientHello, a HelloRetryRequest, or a ServerHello. However, we only implement
			a server so we know it must be a ClientHello
		*/
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 1 {
            return Err(TLSError::InvalidHandshakeError)
        }

        let mut kse_list : Vec<KeyShareEntry> = vec![];

        for _ in 1..length {
        	// Parse a KeyShareEntry
        	kse_list.push(try!(Extension::parse_keyshare_entry(iter)));
        }

        Ok(Extension::KeyShare(KeyShare::ClientHello(kse_list)))
	}

	fn parse_psk_identities<'a>(iter: &mut Iter<'a, u8>) -> Result<Vec<PskIdentity>, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 7 {
            return Err(TLSError::InvalidHandshakeError)
        }

        let mut ret : Vec<PskIdentity> = vec![];

        for _ in 1..length {
        	let first = iter.next().unwrap();
			let second = iter.next().unwrap();

			let length = ((*first as u16) << 8) | (*second as u16);
			if length < 1 {
				return Err(TLSError::InvalidHandshakeError)
			}

			let identity_data : Vec<u8> = iter.take(length as usize).map(|&x| x).collect();

			/*
				This is a code smell, but there's also no clear way to apply the byteorder crate
				to an iterator to generate a u32
			*/

			let b1 = iter.next().unwrap(); let b2 = iter.next().unwrap();
			let b3 = iter.next().unwrap(); let b4 = iter.next().unwrap();
			let obfuscated_age = ((*b1 as u32) << 24) | ((*b2 as u32) << 16) |
									((*b3 as u32) << 8) | (*b4 as u32);

        	ret.push(PskIdentity{identity : identity_data, obfuscated_ticket_age : obfuscated_age});
        }

        Ok(ret)
	}

	fn parse_psk_binders<'a>(iter: &mut Iter<'a, u8>) -> Result<Vec<PskBinderEntry>, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 33 {
            return Err(TLSError::InvalidHandshakeError)
        }

        let mut ret : Vec<PskBinderEntry> = vec![];

        for _ in 1..length {
        	let first = *(iter.next().unwrap());

			if first < 32 {
				return Err(TLSError::InvalidHandshakeError)
			}

			let binder_entry : PskBinderEntry = iter.take(first as usize).map(|&x| x).collect();
			ret.push(binder_entry);
        }

        Ok(ret)
	}

	pub fn parse_preshared_key<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		/*
			Technically, the format of this extension depends on whether we are parsing
			a ClientHello or a ServerHello. However, we only implement
			a server so we know it must be a ClientHello
		*/

		// Parse PskIdentity vector
		let pski_list : Vec<PskIdentity> = try!(Extension::parse_psk_identities(iter));

		// Parse PskBinderEntry vector
		let pskb_list : Vec<PskBinderEntry> = try!(Extension::parse_psk_binders(iter));

		Ok(Extension::PreSharedKey(PreSharedKeyExtension{identities: pski_list, binders : pskb_list}))
	}

	pub fn parse_earlydata<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		/*
			Technically, the format of this extension depends on whether we are parsing
			a ClientHello, EncryptedExtensions, or NewSessionTicket. However, as the server
			we will only ever parse the ClientHello
		*/

		Ok(Extension::EarlyData(EarlyDataIndication{value: EarlyDataIndicationOptions::ClientHello(Empty{})}))
	}

	pub fn parse_supported_versions<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		// TODO: Is it possible for these to ever panic?
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 2 || length > 254 {
            return Err(TLSError::InvalidHandshakeError)
        }
		let mut ret : Vec<ProtocolVersion> = Vec::new();
		for _ in 1..(length/2) {

			let first = iter.next();
			let second = iter.next();
			if first.is_none() || second.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

			ret.push(((*first.unwrap() as u16) << 8) | (*second.unwrap() as u16));
		}

        Ok(Extension::SupportedVersions(SupportedVersions{versions: ret}))
	}

	pub fn parse_cookie<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();
		let second = iter.next().unwrap();

		let length = ((*first as u16) << 8) | (*second as u16);
        if length < 1 {
            return Err(TLSError::InvalidHandshakeError)
        }
		let ret : Vec<u8> = iter.take(length as usize).map(|&x| x).collect();
        Ok(Extension::Cookie(Cookie{cookie : ret}))
	}

	pub fn parse_psk_key_exchange_modes<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		let first = iter.next().unwrap();

		let length = *first as u8;
        if length < 1 {
            return Err(TLSError::InvalidHandshakeError)
        }
        let mut ret : Vec<PskKeyExchangeMode> = vec![];
        for _ in 1..length {
        	let first = iter.next();
        	if first.is_none() {
				return Err(TLSError::InvalidHandshakeError)
			}

        	ret.push(match *first.unwrap() {
        		0 => PskKeyExchangeMode::PskKe,
        		1 => PskKeyExchangeMode::PskDheKe,
        		_ => return Err(TLSError::InvalidHandshakeError)
        	});
        }
        Ok(Extension::PskKeyExchangeModes(PskKeyExchangeModes{ke_modes: ret}))
	}

	// Client will never send this extension, so we don't parse it
	pub fn parse_oldfilters<'a>(iter: &mut Iter<'a, u8>, tlsconfig: &TLS_session) -> Result<Extension, TLSError> {
		Err(TLSError::InvalidHandshakeError)
	}
}
