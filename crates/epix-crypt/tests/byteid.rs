use serde::Deserialize;
#[derive(Deserialize)] struct V { signatures: Vec<S> }
#[derive(Deserialize)] struct S { privatekey_hex:String, data:String, sig_dbl_b64:String, sig_keccak_b64:String }
#[test] fn report_byte_identity() {
    let v: V = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let (mut d, mut k) = (0,0);
    for t in &v.signatures {
        if epix_crypt::sign(&t.data,&t.privatekey_hex).unwrap()==t.sig_dbl_b64 { d+=1; }
        if epix_crypt::sign_keccak(&t.data,&t.privatekey_hex).unwrap()==t.sig_keccak_b64 { k+=1; }
    }
    println!("BYTE-IDENTICAL: dbl {}/{}  keccak {}/{}", d, v.signatures.len(), k, v.signatures.len());
}
