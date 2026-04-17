//! JNI bridge for the NDN BLE test Android app.
//!
//! Exposes NDN packet encoding/decoding to Kotlin via JNI.
//! Build with: `cargo ndk -t arm64-v8a build --release`

use bytes::Bytes;
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::{jbyteArray, jint};

use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, encode_lp_packet};

/// Encode an NDN Interest for the given name URI.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ndnrs_bletest_NdnCodec_nativeEncodeInterest(
    mut env: JNIEnv,
    _class: JClass,
    name: jni::objects::JString,
    nonce: jint,
) -> jbyteArray {
    let name_str: String = match env.get_string(&name) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let parsed: ndn_packet::Name = match name_str.parse() {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };

    let wire = InterestBuilder::new(parsed).build();
    let mut buf = wire.to_vec();

    // Patch nonce.
    let nonce_bytes = (nonce as u32).to_be_bytes();
    for i in 0..buf.len().saturating_sub(5) {
        if buf[i] == 0x0A && buf[i + 1] == 0x04 {
            buf[i + 2..i + 6].copy_from_slice(&nonce_bytes);
            break;
        }
    }

    env.byte_array_from_slice(&buf).unwrap_or(std::ptr::null_mut())
}

/// Wrap a raw NDN packet in an NDNLPv2 LpPacket envelope.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ndnrs_bletest_NdnCodec_nativeWrapLpPacket(
    mut env: JNIEnv,
    _class: JClass,
    payload: jbyteArray,
) -> jbyteArray {
    let input = match env.convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(payload) })
    {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let wire = encode_lp_packet(&input);
    env.byte_array_from_slice(&wire).unwrap_or(std::ptr::null_mut())
}

/// Unwrap an NDNLPv2 LpPacket and return the inner fragment.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_ndnrs_bletest_NdnCodec_nativeUnwrapLpPacket(
    mut env: JNIEnv,
    _class: JClass,
    wire: jbyteArray,
) -> jbyteArray {
    let input = match env.convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(wire) }) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let lp = match LpPacket::decode(Bytes::from(input)) {
        Ok(lp) => lp,
        Err(_) => return std::ptr::null_mut(),
    };

    match lp.fragment {
        Some(frag) => env.byte_array_from_slice(&frag).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}
