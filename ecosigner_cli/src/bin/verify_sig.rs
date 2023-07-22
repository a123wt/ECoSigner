use curv::elliptic::curves::{Point, Secp256k1};
use openssl::{base64, ecdsa::EcdsaSig, nid::Nid, ec};
use anyhow::{anyhow, Context, Result};
use secp256k1::ecdsa::Signature;

fn verify_signature(tbs_base64:String,sig:String,public_key:Point<Secp256k1>)->Result<bool>{
    let tbs_bytes=base64::decode_block(&tbs_base64).map_err(|_| anyhow!("Failed decode to be signed data as base64"))?;
    let sig_bytes=base64::decode_block(&sig).map_err(|_| anyhow!("Failed decode signature as base64"))?;
    let sig_secp256k1=Signature::from_compact(&sig_bytes)?;
    let sig_der=sig_secp256k1.serialize_der();
    let sig_openssl=EcdsaSig::from_der(&sig_der)?;

    let public_key_bytes = public_key.to_bytes(true).to_vec();
    let ecg = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let public_key_ec_point=openssl::ec::EcPoint::from_bytes(ecg.as_ref(), public_key_bytes.as_ref(), &mut ctx)?;
    let public_key_eckey =
        openssl::ec::EcKey::from_public_key(ecg.as_ref(), public_key_ec_point.as_ref()).context("Failed to get public key bytes")?;
    // let public_key_der=public_key_eckey.public_key_to_der()?;
    // let public_key_pkey=PKey::from_ec_key(public_key_eckey)?;
    
    let result=sig_openssl.verify(&tbs_bytes, public_key_eckey.as_ref()).context("Failed to verify signature")?;
    Ok(result)
}

fn main(){
    let tbs_base64="VCAxZnrgVMO8AVRZuKIbOTxbaWU7L1e9Cf/buFlCSGU=".to_string();
    let sig_base64="EQHU9bRkwtBlvURU3QDzmvqKA3Wz8zP5VutsGn+Uzp1VzRno4Xa9ALAa6nAJg8wCy/jdszDsQPq4h5pwiOcn2g==".to_string();
    let public_key:Point<Secp256k1>=serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":[2,166,35,147,113,171,245,157,175,161,12,225,165,194,236,100,99,14,148,162,187,221,200,8,124,161,240,125,68,203,246,175,19]}").unwrap();
    let result=verify_signature(tbs_base64, sig_base64, public_key);
    println!("{:?}",result);
}