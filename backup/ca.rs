extern crate openssl;

use openssl::x509::{X509, X509Name, X509Builder};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;

use std::fs::File;
use std::io::{Write, Result};

fn generate_rsa_key_pair(bits: u32) -> PKey<openssl::pkey::Private> {
    let rsa = Rsa::generate(bits).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn create_self_signed_cert(private_key: &PKey<openssl::pkey::Private>, common_name: &str) -> X509 {
    let mut x509_name = X509Name::builder().unwrap();
    x509_name.append_entry_by_text("CN", common_name).unwrap();
    let x509_name = x509_name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&x509_name).unwrap();
    builder.set_issuer_name(&x509_name).unwrap();
    builder.set_pubkey(private_key).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(private_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn save_pem_to_file(filename: &str, data: &[u8]) -> Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}

fn create_and_sign_cert(root_key: &PKey<openssl::pkey::Private>, subject_name: &str) -> (X509, PKey<openssl::pkey::Private>) {
    let private_key = generate_rsa_key_pair(2048);
    let cert = create_self_signed_cert(&private_key, subject_name);

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&cert.subject_name()).unwrap();
    builder.set_pubkey(&private_key).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.set_issuer_name(&cert.subject_name()).unwrap();
    builder.sign(root_key, MessageDigest::sha256()).unwrap();
    let signed_cert = builder.build();

    (signed_cert, private_key)
}

fn main() {
    // 创建根证书的私钥
    let root_key = generate_rsa_key_pair(2048);
    let root_cert = create_self_signed_cert(&root_key, "Rust CA");

    // 保存根证书和根私钥
    let root_cert_pem = root_cert.to_pem().unwrap();
    let root_key_pem = root_key.private_key_to_pem_pkcs8().unwrap();

    save_pem_to_file("root_cert.pem", &root_cert_pem).unwrap();
    save_pem_to_file("root_key.pem", &root_key_pem).unwrap();
    println!("Root certificate and private key saved.");

    // 使用根证书签发服务器证书
    let (server_cert, server_key) = create_and_sign_cert(&root_key, "Rust Server");

    // 保存服务器证书和私钥
    let server_cert_pem = server_cert.to_pem().unwrap();
    let server_key_pem = server_key.private_key_to_pem_pkcs8().unwrap();

    save_pem_to_file("server_cert.pem", &server_cert_pem).unwrap();
    save_pem_to_file("server_key.pem", &server_key_pem).unwrap();
    println!("Server certificate and private key saved.");
}
