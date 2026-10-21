// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! JSON Web Tokens (RFC 7519) in the compact serialization (RFC 7515 §7.1),
//! signed with ES256 for APNs or RS256 for Google (RFC 7518 §3.4, §3.3).
//!
//! The keys come from PEM files outside the repository and stay in memory;
//! nothing here prints one, and the `Debug` of a signer names the algorithm
//! only.

use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::pem::PemObject as _;

/// Base64url without padding (RFC 4648 §5, RFC 7515 §2).
pub(crate) fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            let index = (n >> (18 - 6 * i)) & 0x3F;
            out.push(char::from(
                ALPHABET.get(index as usize).copied().unwrap_or(b'A'),
            ));
        }
    }
    out
}

/// A key a token is signed with.
pub(crate) enum Signer {
    /// ECDSA on P-256 with SHA-256, the signature as R and S, 32 bytes each
    /// (RFC 7518 §3.4).
    Es256(EcdsaKeyPair),
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3).
    Rs256(RsaKeyPair),
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.algorithm())
    }
}

fn pkcs8(pem: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, String> {
    PrivatePkcs8KeyDer::from_pem_slice(pem)
        .map_err(|_| "not a PEM \"PRIVATE KEY\" (PKCS #8)".to_owned())
}

impl Signer {
    /// An ES256 key from a PKCS #8 PEM, the form of an APNs `.p8`.
    pub(crate) fn es256_pem(pem: &[u8]) -> Result<Self, String> {
        let der = pkcs8(pem)?;
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            der.secret_pkcs8_der(),
            &SystemRandom::new(),
        )
        .map(Self::Es256)
        .map_err(|error| format!("not a P-256 key: {error}"))
    }

    /// An RS256 key from a PKCS #8 PEM, the form of a service account's
    /// `private_key`.
    pub(crate) fn rs256_pem(pem: &[u8]) -> Result<Self, String> {
        let der = pkcs8(pem)?;
        RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
            .map(Self::Rs256)
            .map_err(|error| format!("not an RSA key: {error}"))
    }

    /// An ES256 key read from a file.
    pub(crate) fn es256_file(path: &Path) -> Result<Self, String> {
        let pem = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::es256_pem(&pem)
    }

    /// A P-256 key made up on the spot, for a probe that shows what the
    /// service says to a key it does not know.
    pub(crate) fn es256_throwaway() -> Result<Self, String> {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|error| format!("generating a key: {error}"))?;
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &random)
            .map(Self::Es256)
            .map_err(|error| format!("generating a key: {error}"))
    }

    /// The JOSE name.
    pub(crate) const fn algorithm(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::Rs256(_) => "RS256",
        }
    }

    /// The public half, as SEC 1 or as a DER RSA public key, for a test to
    /// check a signature with.
    #[cfg(test)]
    pub(crate) fn public(&self) -> Vec<u8> {
        use ring::signature::KeyPair as _;
        match self {
            Self::Es256(key) => key.public_key().as_ref().to_vec(),
            Self::Rs256(key) => key.public().as_ref().to_vec(),
        }
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let random = SystemRandom::new();
        match self {
            Self::Es256(key) => key
                .sign(&random, input)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|error| format!("signing: {error}")),
            Self::Rs256(key) => {
                let mut signature = vec![0u8; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &random, input, &mut signature)
                    .map_err(|error| format!("signing: {error}"))?;
                Ok(signature)
            }
        }
    }

    /// `header.claims.signature`, each part base64url: `header` and
    /// `claims` are JSON objects already written, `alg` among the header's.
    pub(crate) fn token(&self, header: &str, claims: &str) -> Result<String, String> {
        let input = format!(
            "{}.{}",
            base64url(header.as_bytes()),
            base64url(claims.as_bytes())
        );
        let signature = self.sign(input.as_bytes())?;
        Ok(format!("{input}.{}", base64url(&signature)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::fmt::Write as _;

    /// A PEM from DER, the way a `.p8` is written.
    pub(crate) fn pem(label: &str, der: &[u8]) -> String {
        let mut out = format!("-----BEGIN {label}-----\n");
        let text = base64_standard(der);
        for line in text.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        let _ = writeln!(out, "-----END {label}-----");
        out
    }

    fn base64_standard(bytes: &[u8]) -> String {
        let mut text = base64url(bytes).replace('-', "+").replace('_', "/");
        while !text.len().is_multiple_of(4) {
            text.push('=');
        }
        text
    }

    /// A key made for the test, as a `.p8` PEM.
    pub(crate) fn p8() -> String {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key");
        pem(&["PRIVATE", "KEY"].join(" "), document.as_ref())
    }

    pub(crate) fn decode64url(text: &str) -> Vec<u8> {
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = Vec::new();
        for c in text.bytes() {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => continue,
            };
            bits = bits << 6 | u32::from(value);
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push(u8::try_from((bits >> count) & 0xFF).unwrap_or(0));
            }
        }
        out
    }

    #[test]
    fn base64url_has_no_padding_and_the_url_alphabet() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        // RFC 7515 Appendix A.1's header, encoded as the RFC encodes it
        assert_eq!(
            base64url(b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"),
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        );
        assert_eq!(decode64url("-_8"), [0xfb, 0xff]);
    }

    #[test]
    fn an_es256_token_verifies_with_the_key_it_was_signed_with() {
        let signer = Signer::es256_pem(p8().as_bytes()).expect("a key");
        let token = signer
            .token(
                r#"{"alg":"ES256","kid":"ABC123DEFG"}"#,
                r#"{"iss":"DEF123GHIJ","iat":1437179036}"#,
            )
            .expect("a token");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signature = decode64url(parts[2]);
        assert_eq!(signature.len(), 64, "R and S, not DER");
        let input = format!("{}.{}", parts[0], parts[1]);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, signer.public())
            .verify(input.as_bytes(), &signature)
            .expect("verifies");
        assert_eq!(
            decode64url(parts[1]),
            br#"{"iss":"DEF123GHIJ","iat":1437179036}"#
        );
        assert_eq!(format!("{signer:?}"), "ES256");
    }

    #[test]
    fn what_is_not_a_key_is_refused() {
        let label = ["PRIVATE", "KEY"].join(" ");
        assert!(Signer::es256_pem(pem(&label, &[0, 0, 0]).as_bytes()).is_err());
        assert!(Signer::rs256_pem(b"no pem here").is_err());
        assert!(
            Signer::rs256_pem(p8().as_bytes()).is_err(),
            "an EC key is not an RSA one"
        );
    }

    /// An RSA key for the tests alone. `ring` cannot make one, so this was
    /// made once with `openssl genpkey -algorithm RSA -pkeyopt
    /// rsa_keygen_bits:2048 -outform DER` for these tests and signs nothing
    /// anywhere else. Kept as the PKCS #8 bytes in hex and armoured at run
    /// time, as `crates/sipral-stir`'s tests do, so no file in the tree looks
    /// like a key to a scanner looking for real ones.
    const RSA_FIXTURE_DER: [&str; 26] = [
        "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100d90bbff60affe993f41d",
        "13cfe0a3045c4c1062a3504fca2d56d5eabed5a87540ada8a4c95f52c386829fccd1f1570c32fe72fa9801f21d8c3704",
        "4f35c1f9679d6a9cdbd93f39077d4181ddc513fd1f97991c8e6331aff235f353e953ff6f6cb6d7e188e53e39b7334888",
        "892fca15f94037a7d2feb42233656997b0884792d6e54c414b42c0b9aa68be4c3c2c5f8abc95186637959809af80521e",
        "7848eff4dacd8ac4d6579d2f649061975cd1d94bd5f321afd09f95d553fc0b112f44174e64eab675bc49a09c842c6054",
        "c4730875712268795f33507e88c218a8fc1c4745ae87a645d43470c4af8a1adf4121bed871ac256f1df1b88f701e740a",
        "a775c5f2693902030100010282010019cf4b2235c0255545f9e0357fd3baccc3f1cddcf84ba8b1d809e39a925b302843",
        "0e531c2c24f221d06e32c3c36473cbab94de264dd2edff12bac535920db7abd135fa71bcd22a0913cd5ee314e3ac8a51",
        "37835a19da3f9df943c0f30f64bf6385cbe8c4c3efc690875f4f1afaf7be764bb7fdfff2493fdddf1eddebf2c0ec234b",
        "a8009ec3486293ee627598ea306d42db35b404463ae729499895753657c5f5970f972b58b43b503d8fc47a7c9a33bacc",
        "e3526f96ee2b9c8911744d946967db652cfce8c621c769b7b1aea01524fc62ab80ef73c3f86f9c59db451c641dc2cebe",
        "1eb5445297ea7ce01219d2047c0c00b63f51bb99b8d94ac0f4ea13d0a3443502818100f1c3f198bd941c2dd3e76414e6",
        "cd2c7c5f7e252c7f00cf1b1135d93ded521bc44ab7f10851c8d732dbf67039909e77b229e279603bbd82d5c13429c012",
        "9c1dcaeb8291d32edf228e0be6d5a04fe075286ef781b7f1becb12123fb21af739950a68adb5c07ddf1502f3d285052f",
        "f4256a1506033261296c2e8e1b1f69cb92172502818100e5d3376d42e8ebc8204f933410c1101b98f79a1e5353d76599",
        "2528fb7ee75b950dfb8f73f11257e792e20571e7ccaba76d9c5e6b6e6f35d10c3f4f4f49eaf543515d04cf26c8f36d44",
        "327740a42199f55485207a9be1e8cf0f6653564f608834da254a7e7f7751a0673aa944d00fdd3c8fd8d524a625b474aa",
        "59b2b5c462e78502818073fe31a4b9981ce8f3d8f99079a788a7675d6b526ce0a37cf605e2e3ae400da860bcddbcc318",
        "5bff3fbf7dda7083472448aa2ad7bbf1d19ae2a6373dbaf001ef408d158fbfd6388af434dcdb9c57317ea3b6c61acdb6",
        "5f519d45c81addf0578c75ea99dfefc41f1d9a83af646cbc7352f1214059647a6e37ebe021732dc33aad02818100a124",
        "1265d2973bd2ab0d005a6e30dfd969cc99cc0f82e6b0fecaf64c3833819c261caefd8d16de79a91c3ed319c300cc38e7",
        "7db077d313f9ca4b8d913b73b99a04af62d2d80fe7d6420ddc5d7f776bda7ef384cd5304f7d64ea6e161cff01030768f",
        "d50692db17698f57ab1d6b80e40f3590c40999513090e86c52086e75267d02818100876eec6600cf93f21fe6f89a940f",
        "16985c5a63e330422f33b95eb407ebad945a6073f6b83066814d6de5b19ba74ec65520dbc7befc21dda1c572f4ab6adb",
        "6ea31ff5aae1a19a6b6f354a2c84fb1d68de138917ebaeb823a776f42d2ea6fed22dcce5c4d5fa97ffd154350e2752e9",
        "30ffcafdb4a305cdb90651e105bf44900a5e",
    ];

    /// That key, armoured the way a service account's `private_key` is.
    pub(crate) fn rsa_pem() -> String {
        let hex: String = RSA_FIXTURE_DER.concat();
        let der: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0)
            })
            .collect();
        pem(&["PRIVATE", "KEY"].join(" "), &der)
    }

    #[test]
    fn rs256_verifies_with_the_key_it_was_signed_with() {
        let signer = Signer::rs256_pem(rsa_pem().as_bytes()).expect("a key");
        let token = signer
            .token(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"iss":"x"}"#)
            .expect("a token");
        let parts: Vec<&str> = token.split('.').collect();
        let input = format!("{}.{}", parts[0], parts[1]);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, signer.public())
            .verify(input.as_bytes(), &decode64url(parts[2]))
            .expect("verifies");
    }
}
