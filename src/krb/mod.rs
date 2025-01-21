/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use nix::unistd::{self, SysconfVar, Uid};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    cell::Cell,
    error,
    ffi::{CStr, CString, FromBytesUntilNulError, IntoStringError, NulError},
    fmt,
    mem::MaybeUninit,
    ops::Deref,
    os::raw,
    ptr,
    result::Result,
    slice,
    str::Utf8Error,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

mod cffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/krbutil.rs"));
}

pub const fn const_cstr(cstr: &[u8]) -> &str {
    match unsafe { CStr::from_bytes_with_nul_unchecked(cstr).to_str() } {
        Ok(s) => s,
        Err(_) => panic!("invalid UTF-8 in C string"),
    }
}

pub const TGS_NAME: &str = const_cstr(cffi::KRB5_TGS_NAME);
pub const ANONYMOUS_REALMSTR: &str = const_cstr(cffi::KRB5_ANONYMOUS_REALMSTR);

#[derive(Copy, Clone)]
struct Context(cffi::krb5_context);

unsafe impl Send for Context {}

thread_local! {
    static CONTEXT: Cell<Context> = Cell::new(Context(
        match unsafe { cffi::krbutil_context() } {
            ctx if !ctx.is_null() => ctx,
            _ => panic!("could not initialize krb5 context"),
        }
    ));
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
        let ctx = CONTEXT.get();

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
        let ctx = CONTEXT.get();

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
        let ctx = CONTEXT.get();

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

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsInfo {
    pub uid: u32,
    pub principal: String,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub renew_until: SystemTime,
}

pub fn default_realm() -> Result<String, Error> {
    let ctx = CONTEXT.get();

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

#[allow(dead_code)]
pub fn default_ccache() -> Result<String, Error> {
    let ctx = CONTEXT.get();

    unsafe {
        let ptr = cffi::krb5_cc_default_name(ctx.0);
        let ccache = CStr::from_ptr(ptr).to_str().map(str::to_owned);
        Ok(ccache?)
    }
}

pub fn local_user(princ: &str) -> Result<String, Error> {
    let size = match unistd::sysconf(SysconfVar::LOGIN_NAME_MAX) {
        Ok(Some(n)) => n as usize,
        Ok(None) | Err(_) => 256,
    };
    let mut user = Vec::<u8>::with_capacity(size);
    let princ = CString::new(princ)?;

    let ctx = CONTEXT.get();

    let ret = unsafe { cffi::krbutil_local_user(ctx.0, user.as_mut_ptr() as *mut raw::c_char, size, princ.as_ptr()) };
    if ret == 0 {
        unsafe { user.set_len(size) };
        Ok(CStr::from_bytes_until_nul(&user)?.to_owned().into_string()?)
    } else {
        Err(ret.into())
    }
}

pub fn destroy_all_ccaches() -> Result<(), Error> {
    let ctx = CONTEXT.get();

    let ret = unsafe { cffi::krbutil_destroy_all_ccaches(ctx.0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(ret.into())
    }
}

impl Credentials {
    pub fn forge(
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

        let ctx = CONTEXT.get();

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

    pub fn fetch(ccache: &str, min_life: Option<&str>, with_crealm: bool) -> Result<Credentials, Error> {
        let mut creds = Credentials(ptr::null_mut());
        let ccache = CString::new(ccache)?;
        let min_life = min_life.map(CString::new).transpose()?;

        let ctx = CONTEXT.get();

        let ret = unsafe {
            cffi::krbutil_fetch_creds(
                ctx.0,
                &mut creds.0,
                ccache.as_ptr(),
                min_life.as_deref().map_or(ptr::null(), CStr::as_ptr),
                with_crealm,
            )
        };
        if ret == 0 {
            Ok(creds)
        } else {
            Err(ret.into())
        }
    }

    pub fn local_user(&self) -> Result<String, Error> {
        let size = match unistd::sysconf(SysconfVar::LOGIN_NAME_MAX) {
            Ok(Some(n)) => n as usize,
            Ok(None) | Err(_) => 256,
        };
        let mut user = Vec::<u8>::with_capacity(size);

        let ctx = CONTEXT.get();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_local_user_creds(ctx.0, user.as_mut_ptr() as *mut raw::c_char, size, self.0) };
        if ret == 0 {
            unsafe { user.set_len(size) };
            Ok(CStr::from_bytes_until_nul(&user)?.to_owned().into_string()?)
        } else {
            Err(ret.into())
        }
    }

    pub fn info(&self) -> Result<CredentialsInfo, Error> {
        fn principal_to_string(princ: cffi::krb5_principal) -> Result<String, Error> {
            let ctx = CONTEXT.get();

            unsafe {
                let mut ptr = ptr::null_mut::<raw::c_char>();
                let ret = cffi::krb5_unparse_name(ctx.0, princ, &mut ptr);
                if ret == 0 {
                    let name = CStr::from_ptr(ptr).to_str().map(str::to_owned);
                    cffi::krb5_free_unparsed_name(ctx.0, ptr);
                    cffi::krb5_free_principal(ctx.0, princ);
                    Ok(name?)
                } else {
                    cffi::krb5_free_principal(ctx.0, princ);
                    Err(ret.into())
                }
            }
        }

        let mut princ = MaybeUninit::uninit();
        let mut times = MaybeUninit::uninit();

        let ctx = CONTEXT.get();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_info_creds(ctx.0, princ.as_mut_ptr(), times.as_mut_ptr(), self.0) };
        if ret == 0 {
            unsafe {
                let princ = princ.assume_init();
                let times = times.assume_init();

                Ok(CredentialsInfo {
                    uid: Uid::current().into(),
                    principal: principal_to_string(princ)?,
                    start_time: UNIX_EPOCH + Duration::from_secs(times.starttime as u64),
                    end_time: UNIX_EPOCH + Duration::from_secs(times.endtime as u64),
                    renew_until: UNIX_EPOCH + Duration::from_secs(times.renew_till as u64),
                })
            }
        } else {
            Err(ret.into())
        }
    }

    #[allow(dead_code)]
    pub fn will_last_for(&self, lifetime: &str) -> Result<bool, Error> {
        let lifetime = CString::new(lifetime)?;
        let mut renewable = false;

        let ctx = CONTEXT.get();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_lasting_creds(ctx.0, lifetime.as_ptr(), &mut renewable, self.0) };
        if ret == 0 {
            Ok(renewable)
        } else {
            Err(ret.into())
        }
    }

    pub fn store(&self) -> Result<(), Error> {
        let ctx = CONTEXT.get();

        assert!(!self.0.is_null());
        let ret = unsafe { cffi::krbutil_store_creds(ctx.0, self.0) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret.into())
        }
    }
}
