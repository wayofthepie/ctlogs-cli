use der_parser::ber::BerObjectContent::{
    BmpString, IA5String, PrintableString, T61String, UTF8String,
};
use encoding::types::Encoding;
use encoding::{all::ISO_8859_1, DecoderTrap};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension, SubjectAlternativeName},
    objects::oid2sn,
    AttributeTypeAndValue, TbsCertificate, X509Name,
};

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct CertInfo {
    pub position: usize,
    pub issuer: Vec<NamePart>,
    pub subject: Vec<NamePart>,
    pub san: Vec<SanObject>,
    pub cert: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SanObject {
    DnsName(String),
    Ipv4Addr(String),
    Ipv6Addr(String),
    Rfc822Name(String),
    Othername(OtherName),
    X400Address(String),
    DirName(Vec<NamePart>),
    InvalidIpAddress(String),
    Unknown(String),
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct OtherName {
    oid: String,
    name: String,
}

impl OtherName {
    pub fn new(oid: String, name: String) -> Self {
        Self { oid, name }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NamePart {
    tag: String,
    value: String,
}

impl NamePart {
    pub fn new(tag: String, value: String) -> Self {
        Self { tag, value }
    }
}

pub fn parse_x509_bytes(bytes: &[u8], position: usize) -> Result<CertInfo, Box<dyn Error>> {
    let (_, cert) = x509_parser::parse_x509_der(bytes)?;
    let mut info = extract_cert_info(cert.tbs_certificate, position)?;
    info.cert = base64::encode(&bytes);
    Ok(info)
}

fn extract_cert_info(cert: TbsCertificate, position: usize) -> Result<CertInfo, Box<dyn Error>> {
    let mut cert_info = CertInfo::default();
    cert_info.position = position;
    cert_info.issuer = x509_name_to_name_parts(cert.issuer, position);
    cert_info.subject = x509_name_to_name_parts(cert.subject, position);
    cert_info.san = cert
        .extensions
        .into_iter()
        .filter_map(|(_, extension)| match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(handle_san(san)),
            _ => None,
        })
        .flatten()
        .collect();
    Ok(cert_info)
}

fn x509_name_to_name_parts(name: X509Name, position: usize) -> Vec<NamePart> {
    name.rdn_seq
        .into_iter()
        .flat_map(|rdn| {
            rdn.set
                .into_iter()
                .map(|a| attrribute_to_name_part(a, position))
        })
        .collect::<Vec<NamePart>>()
}

fn attrribute_to_name_part(attr: AttributeTypeAndValue, position: usize) -> NamePart {
    let AttributeTypeAndValue {
        attr_type,
        attr_value,
    } = attr;
    let sn = match oid2sn(&attr_type) {
        Ok(sn) => sn.to_owned(),
        Err(_) => attr_type.to_id_string(),
    };
    let value = match attr_value.content {
        UTF8String(value) => value.to_owned(),
        PrintableString(value) => value.to_owned(),
        IA5String(value) => value.to_owned(),
        T61String(bytes) => match ISO_8859_1.decode(bytes, DecoderTrap::Replace) {
            Ok(decoded) => decoded,
            Err(_) => {
                eprintln!("error decoding");
                base64::encode(bytes)
            }
        },
        BmpString(bytes) => decode_bmpstring(bytes),
        _ => {
            eprintln!(
                "Found unknown attribute value type {:?} as position {}",
                attr_value, position
            );
            "".to_owned()
        }
    };
    NamePart { tag: sn, value }
}

fn decode_bmpstring(bytes: &[u8]) -> String {
    let decoded = bytes
        .chunks(2)
        .map(|slice| ((slice[0] as u16) << 8) | slice[1] as u16)
        .collect::<Vec<u16>>();
    String::from_utf16_lossy(&decoded)
}

fn handle_san(san: &SubjectAlternativeName) -> Vec<SanObject> {
    san.general_names
        .iter()
        .map(|name| match name {
            &GeneralName::IPAddress(bytes) => bytes_to_san_ip(bytes),
            &GeneralName::RFC822Name(name) => SanObject::Rfc822Name(name.to_owned()),
            &GeneralName::DNSName(name) => SanObject::DnsName(name.to_string()),
            GeneralName::OtherName(oid, bytes) => {
                SanObject::Othername(OtherName::new(oid.to_string(), base64::encode(bytes)))
            }
            _ => SanObject::Unknown("".into()),
        })
        .collect()
}

fn bytes_to_san_ip(bytes: &[u8]) -> SanObject {
    let len = bytes.len();
    if len == 4 {
        SanObject::Ipv4Addr(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
    } else if len == 16 {
        SanObject::Ipv6Addr(
            Ipv6Addr::new(
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            )
            .to_string(),
        )
    } else {
        // TODO think of a better way of signifying invalid data here
        SanObject::InvalidIpAddress("Invalid".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::{parse_x509_bytes, NamePart, OtherName, SanObject};

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_bmpstring_from_subject() {
        let common_name = NamePart {
            tag: "O".to_owned(),
            value: "Bnei Baruch Association - עמותת בני ברוך".to_owned(),
        };
        let cert = include_str!("../resources/test/cert__subject_with_bmpstring.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.subject.contains(&common_name));
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_t61string_from_subject() {
        let common_name = NamePart {
            tag: "CN".to_owned(),
            value: "*.ithenticate.com".to_owned(),
        };
        let cert = include_str!("../resources/test/cert__subject_with_t61string.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.subject.contains(&common_name));
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_subject_into_attribute_value_pairs() {
        let common_name = NamePart {
            tag: "CN".to_owned(),
            value: "ctlogs-test".to_owned(),
        };
        let country = NamePart {
            tag: "C".to_owned(),
            value: "IE".to_owned(),
        };
        let org = NamePart {
            tag: "O".to_owned(),
            value: "nocht".to_owned(),
        };
        let cert = include_str!("../resources/test/cert__issuer_with_multipart_rdn.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.subject.contains(&common_name));
        assert!(info.subject.contains(&country));
        assert!(info.subject.contains(&org));
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_issuer_into_attribute_value_pairs() {
        let common_name = NamePart {
            tag: "CN".to_owned(),
            value: "ctlogs-test".to_owned(),
        };
        let country = NamePart {
            tag: "C".to_owned(),
            value: "IE".to_owned(),
        };
        let org = NamePart {
            tag: "O".to_owned(),
            value: "nocht".to_owned(),
        };
        let cert = include_str!("../resources/test/cert__issuer_with_multipart_rdn.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.issuer.contains(&common_name));
        assert!(info.issuer.contains(&country));
        assert!(info.issuer.contains(&org));
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_othername_in_san_and_save_base64_encoded() {
        let cert = include_str!("../resources/test/cert__san_with_othername.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::Othername(OtherName::new(
                "1.2".to_owned(),
                "oBEMD3Rlc3Qgb3RoZXIgbmFtZQ==".to_owned()
            ))]
        );
    }

    #[tokio::test]
    async fn should_serialize_san_object_fields_with_snake_case() {
        let san_objects = vec![
            SanObject::DnsName("".to_owned()),
            SanObject::Rfc822Name("".to_owned()),
            SanObject::Ipv4Addr("".to_owned()),
            SanObject::Ipv6Addr("".to_owned()),
            SanObject::Othername(OtherName::new("".to_owned(), "".to_owned())),
            SanObject::InvalidIpAddress("".to_owned()),
        ];
        let san_objects_str = serde_json::to_string(&san_objects).unwrap();
        assert_eq!(
            san_objects_str,
            format!(
                "{}{}",
                r#"[{"dns_name":""},{"rfc822_name":""},{"ipv4_addr":""},"#,
                r#"{"ipv6_addr":""},{"othername":{"oid":"","name":""}},{"invalid_ip_address":""}]"#
            )
        );
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_san_with_rfc822name() {
        let cert = include_str!("../resources/test/cert__san_with_rfc822name.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::Rfc822Name("test@c.com".to_owned())]
        );
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_correctly_decode_san_with_ipv6() {
        let cert = include_str!("../resources/test/cert__san_with_ipv6.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::Ipv6Addr("fe80::76d0:2bff:fec6:a415".to_owned())]
        );
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_correctly_decode_san_with_ipv4() {
        let cert = include_str!("../resources/test/cert__san_with_ipv4.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::Ipv4Addr("192.168.1.1".to_owned())]
        );
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_correctly_decode_san_with_dns() {
        let cert = include_str!("../resources/test/cert__san_with_dns.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::DnsName("192.168.1.1".to_owned())]
        );
    }
}
