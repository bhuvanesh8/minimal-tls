use structures::{TLSError, AlertDescription};

pub fn error_to_alert(err: TLSError) -> Option<AlertDescription> {

    // Not all errors require sending alerts

    match err {
        InvalidCertificatePath => None,
        InvalidPrivateKeyPath => None,
        InvalidCertificateFile => None,
        InvalidPrivateKeyFile => None,
        CryptoError,
        InvalidState,
        InvalidMessage,
        ReadError => {
            // We can try to send an alert here
            Some
        },
        WriteError,
        InvalidHandshakeError,
        InvalidHandshakeVersionError,
        InvalidCiphertextHeader,
        InvalidHandshakeCompression,
        InvalidCipherSuite,
        InvalidExtensionLength,
        InvalidClientHello,
        InvalidTHMessage,
        UnsupportedCipherSuite,
        UnsupportedNamedGroup,
        InvalidClientHelloExtensions,
        DuplicateExtensions,
        MissingExtension,
        InvalidTLSSupportedVersion,
        InvalidKeyShare,
        InvalidKeyExchange,
        SignatureError => Some(AlertDescription::BadRecordMac),
        AEADError => Some(AlertDescription::BadRecordMac,
        ConnectionClosed => None
    }
}
