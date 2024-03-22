/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use core::ffi::FromBytesUntilNulError;
use lazy_static::lazy_static;
use nix::unistd::{self, SysconfVar};
use serde::{
    de::{value::BytesDeserializer, Error as DeserializeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    error,
    ffi::{CStr, CString, IntoStringError, NulError},
    fmt, io, mem,
    ops::Deref,
    os::raw,
    ptr,
    result::Result,
    slice,
    str::Utf8Error,
    sync::Mutex,
};

mod cffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/krbutil.rs"));
}

pub const TGS_NAME: &str = match unsafe { CStr::from_bytes_with_nul_unchecked(cffi::KRB5_TGS_NAME).to_str() } {
    Ok(str) => str,
    Err(_) => panic!("invalid UTF-8 in KRB5_TGS_NAME"),
};

struct Context(cffi::krb5_context);

unsafe impl Send for Context {}

lazy_static! {
    static ref CONTEXT: Mutex<Context> = unsafe { Mutex::new(Context(cffi::krbutil_context())) };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Error(cffi::krb5_error_code);

#[repr(i32)]
pub enum ErrorKind {
    CredCacheIO = cffi::KRB5_CC_IO,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self(kind as i32)
    }
}

impl DeserializeError for Error {
    fn custom<T>(_: T) -> Self
    where
        T: fmt::Display,
    {
        Self(libc::ENOMEM)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ctx = CONTEXT.lock().unwrap();

        unsafe {
            let err = cffi::krb5_get_error_message(ctx.0, self.0);
            let res = f.write_str(CStr::from_ptr(err).to_str().unwrap());
            cffi::krb5_free_error_message(ctx.0, err);
            res
        }
    }
}

impl From<cffi::krb5_error_code> for Error {
    fn from(err: cffi::krb5_error_code) -> Self {
        Self(err)
    }
}

impl From<NulError> for Error {
    fn from(_: NulError) -> Self {
        Self(cffi::KRB5_ERR_INVALID_UTF8)
    }
}

impl From<FromBytesUntilNulError> for Error {
    fn from(_: FromBytesUntilNulError) -> Self {
        Self(cffi::KRB5_ERR_INVALID_UTF8)
    }
}

impl From<IntoStringError> for Error {
    fn from(_: IntoStringError) -> Self {
        Self(cffi::KRB5_ERR_INVALID_UTF8)
    }
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self(cffi::KRB5_ERR_INVALID_UTF8)
    }
}

impl Serialize for cffi::krb5_data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unsafe { serializer.serialize_bytes(slice::from_raw_parts(self.data as *const u8, self.length as usize)) }
    }
}

impl<'a> Deserialize<'a> for cffi::krb5_data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct DataVisitor;

        impl<'a> Visitor<'a> for DataVisitor {
            type Value = cffi::krb5_data;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a byte buffer")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DeserializeError,
            {
                unsafe {
                    let data = libc::malloc(mem::size_of_val(v)) as *mut u8;
                    if data.is_null() {
                        return Err(E::custom(io::ErrorKind::OutOfMemory));
                    }
                    data.copy_from_nonoverlapping(v.as_ptr(), v.len());

                    Ok(cffi::krb5_data {
                        magic: cffi::KV5M_DATA,
                        data: data as *mut i8,
                        length: v.len().try_into().map_err(E::custom)?,
                    })
                }
            }
        }

        deserializer.deserialize_bytes(DataVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials(cffi::krb5_data);

unsafe impl Send for Credentials {}

impl TryFrom<&[u8]> for Credentials {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let deserializer = BytesDeserializer::<'_, Error>::new(bytes);
        let data = cffi::krb5_data::deserialize(deserializer)?;

        Ok(Self(data))
    }
}

impl Deref for Credentials {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.0.data as *const u8, self.0.length as usize) }
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        let ctx = CONTEXT.lock().unwrap();

        unsafe { cffi::krb5_free_data_contents(ctx.0, &mut self.0) }
    }
}

pub fn default_realm() -> Result<String, Error> {
    let ctx = CONTEXT.lock().unwrap();

    unsafe {
        let mut ptr = ptr::null_mut::<raw::c_char>();
        let ret = cffi::krb5_get_default_realm(ctx.0, &mut ptr);
        if ret == 0 {
            let realm = CStr::from_ptr(ptr).to_str()?.to_owned();
            cffi::krb5_free_default_realm(ctx.0, ptr);
            Ok(realm)
        } else {
            cffi::krb5_free_default_realm(ctx.0, ptr);
            Err(ret.into())
        }
    }
}

pub fn local_user(princ: &str) -> Result<String, Error> {
    let size = match unistd::sysconf(SysconfVar::LOGIN_NAME_MAX) {
        Ok(Some(n)) => n as usize,
        Ok(None) | Err(_) => 256,
    };
    let mut user = Vec::<u8>::with_capacity(size);
    let princ = CString::new(princ)?;

    let ctx = CONTEXT.lock().unwrap();

    let ret = unsafe { cffi::krbutil_local_user(ctx.0, user.as_mut_ptr() as *mut raw::c_char, size, princ.as_ptr()) };
    if ret == 0 {
        unsafe { user.set_len(size) };
        Ok(CStr::from_bytes_until_nul(&user)?.to_owned().into_string()?)
    } else {
        Err(ret.into())
    }
}

pub fn forge_credentials(
    clnt_princ: &str,
    serv_princ: &str,
    enc_type: &str,
    tkt_flags: &str,
    start_time: Option<&str>,
    end_time: Option<&str>,
    renew_till: Option<&str>,
) -> Result<Credentials, Error> {
    let mut creds = unsafe { Credentials(mem::zeroed()) };
    let clnt_princ = CString::new(clnt_princ)?;
    let serv_princ = CString::new(serv_princ)?;
    let enc_type = CString::new(enc_type)?;
    let tkt_flags = CString::new(tkt_flags)?;
    let start_time = start_time.map(CString::new).transpose()?;
    let end_time = end_time.map(CString::new).transpose()?;
    let renew_till = renew_till.map(CString::new).transpose()?;

    let ctx = CONTEXT.lock().unwrap();

    let ret = unsafe {
        cffi::krbutil_forge_creds(
            ctx.0,
            &mut creds.0,
            clnt_princ.as_ptr(),
            serv_princ.as_ptr(),
            enc_type.as_ptr(),
            tkt_flags.as_ptr(),
            start_time.as_deref().map_or(ptr::null(), CStr::as_ptr),
            end_time.as_deref().map_or(ptr::null(), CStr::as_ptr),
            renew_till.as_deref().map_or(ptr::null(), CStr::as_ptr),
        )
    };
    if ret == 0 {
        Ok(creds)
    } else {
        Err(ret.into())
    }
}

impl Credentials {
    pub fn local_user(&self) -> Result<String, Error> {
        let size = match unistd::sysconf(SysconfVar::LOGIN_NAME_MAX) {
            Ok(Some(n)) => n as usize,
            Ok(None) | Err(_) => 256,
        };
        let mut user = Vec::<u8>::with_capacity(size);

        let ctx = CONTEXT.lock().unwrap();

        let ret =
            unsafe { cffi::krbutil_local_user_creds(ctx.0, user.as_mut_ptr() as *mut raw::c_char, size, &self.0) };
        if ret == 0 {
            unsafe { user.set_len(size) };
            Ok(CStr::from_bytes_until_nul(&user)?.to_owned().into_string()?)
        } else {
            Err(ret.into())
        }
    }

    pub fn store(&self) -> Result<(), Error> {
        let ctx = CONTEXT.lock().unwrap();

        let ret = unsafe { cffi::krbutil_store_creds(ctx.0, &self.0) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }
}
