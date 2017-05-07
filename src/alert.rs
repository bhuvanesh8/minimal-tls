use structures::{TLSError, AlertDescription};

pub fn parse_alertdesc(desc: u8) -> AlertDescription {
    match desc {
        0 => AlertDescription::CloseNotify,
        10 => AlertDescription::UnexpectedMessage,
        20 => AlertDescription::BadRecordMac,
        21 => AlertDescription::DecryptionFailedReserved,
        22 => AlertDescription::RecordOverflow,
        30 => AlertDescription::DecompressionFailureReserved,
        40 => AlertDescription::HandshakeFailure,
        41 => AlertDescription::NoCertificateReserved,
        42 => AlertDescription::BadCertificate,
        43 => AlertDescription::UnsupportedCertificate,
        44 => AlertDescription::CertificateRevoked,
        45 => AlertDescription::CertificateExpired,
        46 => AlertDescription::CertificateUnknown,
        47 => AlertDescription::IllegalParameter,
        48 => AlertDescription::UnknownCa,
        49 => AlertDescription::AccessDenied,
        50 => AlertDescription::DecodeError,
        51 => AlertDescription::DecryptError,
        60 => AlertDescription::ExportRestrictionReserved,
        70 => AlertDescription::ProtocolVersion,
        71 => AlertDescription::InsufficientSecurity,
        80 => AlertDescription::InternalError,
        86 => AlertDescription::InappropriateFallback,
        90 => AlertDescription::UserCanceled,
        100 => AlertDescription::NoRenegotiationReserved,
        109 => AlertDescription::MissingExtension,
        110 => AlertDescription::UnsupportedExtension,
        111 => AlertDescription::CertificateUnobtainable,
        112 => AlertDescription::UnrecognizedName,
        113 => AlertDescription::BadCertificateStatusResponse,
        114 => AlertDescription::BadCertificateHashValue,
        115 => AlertDescription::UnknownPskIdentity,
        116 => AlertDescription::CertificateRequired,
        _ => {
            // According to the spec, unknown alerts are to be treated as fatal
            AlertDescription::IllegalParameter
        }
    }
}

// Not all errors require sending alerts
pub fn error_to_alert(err: TLSError) -> Option<AlertDescription> {
    match err {
        InvalidCertificatePath => None,
        InvalidPrivateKeyPath => None,
        InvalidCertificateFile => None,
        InvalidPrivateKeyFile => None,
        CryptoInitError => None,
        InvalidState => None,
        InvalidMessage => Some(AlertDescription::UnexpectedMessage),
        ReadError => {
            // We can try to send an alert here
            Some(AlertDescription::InternalError)
        },
        WriteError => {
            // If we can't write, we can't send an alert
            None
        },
        InvalidHandshakeError => Some(AlertDescription::DecodeError),
        InvalidMessageLength => Some(AlertDescription::IllegalParameter),
        InvalidMessagePadding => Some(AlertDescription::DecodeError),
        InvalidHandshakeVersionError => Some(AlertDescription::ProtocolVersion),
        InvalidCiphertextHeader => Some(AlertDescription::UnexpectedMessage),
        InvalidHandshakeCompression => Some(AlertDescription::IllegalParameter),
        InvalidCipherSuite => Some(AlertDescription::DecodeError),
        InvalidTHMessage => Some(AlertDescription::UnexpectedMessage),
        UnsupportedCipherSuite => Some(AlertDescription::HandshakeFailure),
        UnsupportedNamedGroup => Some(AlertDescription::IllegalParameter),
        DuplicateExtensions => Some(AlertDescription::IllegalParameter),
        MissingExtension => Some(AlertDescription::MissingExtension),
        InvalidTLSSupportedVersion => Some(AlertDescription::ProtocolVersion),
        InvalidKeyShare => Some(AlertDescription::HandshakeFailure),
        InvalidKeyExchange => Some(AlertDescription::DecryptError),
        SignatureError => Some(AlertDescription::BadRecordMac),
        AEADError => Some(AlertDescription::BadRecordMac),
        ConnectionClosed => None
    }
}
