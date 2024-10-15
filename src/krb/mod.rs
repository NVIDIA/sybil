/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::utils::*;

use nix::unistd::{self, SysconfVar};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    error,
    ffi::{CStr, CString, FromBytesUntilNulError, IntoStringError, NulError},
    fmt,
    ops::Deref,
    os::raw,
    ptr,
    result::Result,
    slice,
    str::Utf8Error,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

mod cffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/krbutil.rs"));
}

pub const TGS_NAME: &str = const_cstr(cffi::KRB5_TGS_NAME);
pub const ANONYMOUS_REALMSTR: &str = const_cstr(cffi::KRB5_ANONYMOUS_REALMSTR);

struct Context(cffi::krb5_context);

unsafe impl Send for Context {}

fn context() -> &'static Mutex<Context> {
    static CONTEXT: OnceLock<Mutex<Context>> = OnceLock::new();

    CONTEXT.get_or_init(|| Mutex::new(Context(unsafe { cffi::krbutil_context() })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Error(cffi::krb5_error_code);

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ctx = context().lock().unwrap();

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

impl From<SystemTimeError> for Error {
    fn from(_: SystemTimeError) -> Self {
        Self(cffi::KRB5KRB_AP_ERR_TKT_EXPIRED)
    }
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "&[u8]")]
pub struct Credentials(*mut cffi::krb5_data);

unsafe impl Send for Credentials {}

impl Drop for Credentials {
    fn drop(&mut self) {
        let ctx = context().lock().unwrap();

        if !self.0.is_null() {
            unsafe {
                libc::explicit_bzero((*self.0).data as *mut raw::c_void, (*self.0).length as usize);
                cffi::krb5_free_data(ctx.0, self.0);
            }
        }
    }
}

impl Serialize for Credentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self)
    }
}

impl TryFrom<&[u8]> for Credentials {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let ctx = context().lock().unwrap();

        unsafe {
            let data = cffi::krb5_data {
                magic: cffi::KV5M_DATA,
                data: bytes.as_ptr() as *mut raw::c_char,
                length: bytes.len().try_into().map_err(|_| libc::ENOMEM)?,
            };
            let mut creds = ptr::null_mut::<cffi::krb5_data>();

            let ret = cffi::krb5_copy_data(ctx.0, &data, &mut creds);
            if ret == 0 {
                Ok(Credentials(creds))
            } else {
                Err(ret.into())
            }
        }
    }
}

impl Deref for Credentials {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        assert!(!self.0.is_null());
        unsafe { slice::from_raw_parts((*self.0).data as *const u8, (*self.0).length as usize) }
    }
}

pub fn default_realm() -> Result<String, Error> {
    let ctx = context().lock().unwrap();

    unsafe {
        let mut ptr = ptr::null_mut::<raw::c_char>();
        let ret = cffi::krb5_get_default_realm(ctx.0, &mut ptr);
        if ret == 0 {
            let realm = CStr::from_ptr(ptr).to_str().map(str::to_owned);
            cffi::krb5_free_default_realm(ctx.0, ptr);
            Ok(realm?)
        } else {
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

    let ctx = context().lock().unwrap();

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
    let mut creds = Credentials(ptr::null_mut());
    let clnt_princ = CString::new(clnt_princ)?;
    let serv_princ = CString::new(serv_princ)?;
    let enc_type = CString::new(enc_type)?;
    let tkt_flags = CString::new(tkt_flags)?;
    let start_time = start_time.map(CString::new).transpose()?;
    let end_time = end_time.map(CString::new).transpose()?;
    let renew_till = renew_till.map(CString::new).transpose()?;

    let ctx = context().lock().unwrap();

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

pub fn fetch_credentials(ccache: &str, min_life: Option<&str>) -> Result<Credentials, Error> {
    let mut creds = Credentials(ptr::null_mut());
    let ccache = CString::new(ccache)?;
    let min_life = min_life.map(CString::new).transpose()?;

    let ctx = context().lock().unwrap();

    let ret = unsafe {
        cffi::krbutil_fetch_creds(
            ctx.0,
            &mut creds.0,
            ccache.as_ptr(),
            min_life.as_deref().map_or(ptr::null(), CStr::as_ptr),
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

        let ctx = context().lock().unwrap();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_local_user_creds(ctx.0, user.as_mut_ptr() as *mut raw::c_char, size, self.0) };
        if ret == 0 {
            unsafe { user.set_len(size) };
            Ok(CStr::from_bytes_until_nul(&user)?.to_owned().into_string()?)
        } else {
            Err(ret.into())
        }
    }

    pub fn lifetime(&self) -> Result<SystemTime, Error> {
        let mut lifetime: libc::time_t = 0;
        let ctx = context().lock().unwrap();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_lifetime_creds(ctx.0, &mut lifetime, self.0) };
        if ret == 0 {
            Ok(UNIX_EPOCH + Duration::from_secs(lifetime as u64))
        } else {
            Err(ret.into())
        }
    }

    pub fn store(&self) -> Result<(), Error> {
        let ctx = context().lock().unwrap();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_store_creds(ctx.0, self.0) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }
}
