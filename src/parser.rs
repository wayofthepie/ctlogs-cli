use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension, SubjectAlternativeName},
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
    cert_info.issuer = cert.issuer.to_string();
    cert_info.subject = cert.subject.to_string();
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
    use super::{parse_x509_bytes, OtherName, SanObject};

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
