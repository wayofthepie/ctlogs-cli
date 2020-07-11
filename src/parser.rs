use der_parser::ber::BerObjectContent;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};
use x509_parser::{
    objects::{oid2nid, Nid},
    TbsCertificate,
};

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct CertInfo {
    pub position: usize,
    pub issuer: String,
    pub subject: String,
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
    Othername(String),
    X400Address(String),
    Unknown(String),
}

pub fn parse_x509_bytes(
    bytes: &[u8],
    cert_end_index: usize,
    position: usize,
) -> Result<CertInfo, Box<dyn Error>> {
    let (_, cert) = x509_parser::parse_x509_der(&bytes[..cert_end_index])?;
    let mut info = extract_cert_info(cert.tbs_certificate, position)?;
    info.cert = base64::encode(&bytes[..cert_end_index]);
    Ok(info)
}

fn extract_cert_info(cert: TbsCertificate, position: usize) -> Result<CertInfo, Box<dyn Error>> {
    let mut cert_info = CertInfo::default();
    cert_info.position = position;
    cert_info.issuer = cert.issuer.to_string();
    cert_info.subject = cert.subject.to_string();
    for extension in cert.extensions {
        if let Ok(Nid::SubjectAltName) = oid2nid(&extension.oid) {
            cert_info.san = parse_san(extension.value, position)?;
        }
    }
    Ok(cert_info)
}

fn parse_san(bytes: &[u8], position: usize) -> Result<Vec<SanObject>, Box<dyn Error>> {
    let (_, obj) = der_parser::parse_der(bytes)?;
    let san_objects = obj
        .as_sequence()?
        .iter()
        .map(|item| match item.content {
            BerObjectContent::Unknown(tag, bytes) => match tag.0 {
                // othername
                // TODO decode this correctly and not just as base64
                0 => SanObject::Othername(base64::encode(&bytes)),
                // rfc822name
                // TODO emails can have non-utf8 characters,
                // they should be accounted for here too
                1 => SanObject::Rfc822Name(String::from_utf8_lossy(bytes).to_string()),
                // dns name
                2 => SanObject::DnsName(String::from_utf8_lossy(bytes).to_string()),
                // x400Address
                3 => {
                    // TODO construct a cert with an x400Address in the san, openssl
                    // does not seem to support this. One may exist in the ct logs or
                    // we can hand create one.
                    eprintln!("Encountered x400 address at position {}", position);
                    SanObject::Unknown(String::from_utf8_lossy(bytes).to_string())
                }
                // ip address
                7 => bytes_to_san_ip(&bytes),
                _ => {
                    eprintln!("Encountered unknown tag {} at position {}", tag, position);
                    SanObject::Unknown(String::from_utf8_lossy(bytes).to_string())
                }
            },
            _ => {
                eprintln!(
                    "Encountered unknown ber object {:?} at position {}",
                    item, position
                );
                SanObject::Unknown(String::from_utf8_lossy(bytes).to_string())
            }
        })
        .collect();
    Ok(san_objects)
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
        SanObject::Ipv4Addr("Invalid".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::{parse_x509_bytes, SanObject};

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_othername_in_san_and_save_base64_encoded() {
        let cert = include_str!("../resources/test/cert__san_with_othername.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, bytes.len(), 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::Othername(
                "BgEqoBEMD3Rlc3Qgb3RoZXIgbmFtZQ==".to_owned()
            )]
        );
    }

    #[tokio::test]
    async fn should_serialize_san_object_fields_with_snake_case() {
        let san_objects = vec![
            SanObject::DnsName("".to_owned()),
            SanObject::Rfc822Name("".to_owned()),
            SanObject::Ipv4Addr("".to_owned()),
            SanObject::Ipv6Addr("".to_owned()),
            SanObject::Othername("".to_owned()),
            SanObject::Unknown("".to_owned()),
        ];
        let san_objects_str = serde_json::to_string(&san_objects).unwrap();
        assert_eq!(
            san_objects_str,
            r#"[{"dns_name":""},{"rfc822_name":""},{"ipv4_addr":""},{"ipv6_addr":""},{"othername":""},{"unknown":""}]"#
        );
    }

    #[tokio::test]
    async fn parse_x509_bytes_should_decode_san_with_rfc822name() {
        let cert = include_str!("../resources/test/cert__san_with_rfc822name.crt").trim();
        let bytes = base64::decode(cert).unwrap();
        let result = parse_x509_bytes(&bytes, bytes.len(), 0);
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
        let result = parse_x509_bytes(&bytes, bytes.len(), 0);
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
        let result = parse_x509_bytes(&bytes, bytes.len(), 0);
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
        let result = parse_x509_bytes(&bytes, bytes.len(), 0);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().san,
            vec![SanObject::DnsName("192.168.1.1".to_owned())]
        );
    }
}
