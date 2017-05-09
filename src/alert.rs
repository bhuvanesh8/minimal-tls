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
        TLSError::InvalidCertificatePath => None,
        TLSError::InvalidCertificate => None,
        TLSError::InvalidPrivateKeyPath => None,
        TLSError::InvalidPrivateKey => None,
        TLSError::InvalidCertificateFile => None,
        TLSError::InvalidPrivateKeyFile => None,
        TLSError::CryptoInitError => None,
        TLSError::InvalidState => None,
        TLSError::InvalidMessage => Some(AlertDescription::UnexpectedMessage),
        TLSError::ReadError => {
            // We can try to send an alert here
            Some(AlertDescription::InternalError)
        },
        TLSError::WriteError => {
            // If we can't write, we can't send an alert
            None
        },
        TLSError::InvalidHandshakeError => Some(AlertDescription::DecodeError),
        TLSError::InvalidMessageLength => Some(AlertDescription::IllegalParameter),
        TLSError::InvalidMessagePadding => Some(AlertDescription::DecodeError),
        TLSError::InvalidHandshakeVersionError => Some(AlertDescription::ProtocolVersion),
        TLSError::InvalidCiphertextHeader => Some(AlertDescription::UnexpectedMessage),
        TLSError::InvalidHandshakeCompression => Some(AlertDescription::IllegalParameter),
        TLSError::InvalidCipherSuite => Some(AlertDescription::DecodeError),
        TLSError::InvalidTHMessage => Some(AlertDescription::UnexpectedMessage),
        TLSError::UnsupportedCipherSuite => Some(AlertDescription::HandshakeFailure),
        TLSError::UnsupportedNamedGroup => Some(AlertDescription::IllegalParameter),
        TLSError::DuplicateExtensions => Some(AlertDescription::IllegalParameter),
        TLSError::MissingExtension => Some(AlertDescription::MissingExtension),
        TLSError::InvalidTLSSupportedVersion => Some(AlertDescription::ProtocolVersion),
        TLSError::InvalidKeyShare => Some(AlertDescription::HandshakeFailure),
        TLSError::InvalidKeyExchange => Some(AlertDescription::DecryptError),
        TLSError::SignatureError => Some(AlertDescription::BadRecordMac),
        TLSError::AEADError => Some(AlertDescription::BadRecordMac),
        TLSError::ConnectionClosed => None
    }
}
