/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

mod ops;
mod utils;
mod spank {
    #![allow(clippy::upper_case_acronyms)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(unused_imports)]
    include!(concat!(env!("OUT_DIR"), "/spank.rs"));
}

use crate::trace::ErrorChainExt;
use utils::SharedMemory;

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    env,
    error::Error,
    ffi::{CStr, CString},
    io::{self, ErrorKind, LineWriter},
    os::raw::{c_char, c_int, c_uint},
    slice, str,
};
use tokio::runtime::{self, Runtime};
use tracing_subscriber::fmt::MakeWriter;

const ERROR_PREFIX: &str = "spank_sybil";

const OPT_MIN_TKT_LIFETIME: &str = "min_tkt_lifetime";
const ENV_MIN_TKT_LIFETIME: &str = "SYBIL_MIN_TKT_LIFETIME";

#[no_mangle]
#[used]
pub static plugin_type: [u8; 6] = *b"spank\0";
#[no_mangle]
#[used]
pub static plugin_name: [u8; 6] = *b"sybil\0";
#[no_mangle]
#[used]
pub static mut plugin_version: c_uint = spank::SLURM_VERSION_NUMBER;
#[no_mangle]
#[used]
pub static mut spank_plugin_version: c_uint = utils::cargo_package_version();

thread_local! {
    static RUNTIME: RefCell<Runtime> = panic!("uninitialized runtime");
    static JOB_ID: Cell<u32> = panic!("uninitialized job ID");
    static SPANK_ERROR: Cell<Option<SpankError>> = const { Cell::new(None) };
}

pub struct SpankLogger;

impl io::Write for SpankLogger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for str in String::from_utf8_lossy(buf).lines() {
            let msg = CString::new(format!("{ERROR_PREFIX}: {str}"))?;
            unsafe { spank::slurm_spank_log(c"%s".as_ptr(), msg.as_ptr()) };
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SpankLogger {
    type Writer = LineWriter<Self>;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter::new(Self)
    }
}

enum SpankError {
    Fatal(String),
    Defer(SharedMemory),
}

trait SpankErrorExt {
    fn fatal(&self) -> SpankError;
    fn defer(&self) -> SpankError;
}

impl<E: Error + ?Sized> SpankErrorExt for E {
    fn fatal(&self) -> SpankError {
        SpankError::Fatal(self.chain())
    }

    fn defer(&self) -> SpankError {
        SpankError::open_shmem(self.chain().as_bytes().into()).unwrap()
    }
}

impl SpankError {
    fn open_shmem(error: Option<&[u8]>) -> Option<Self> {
        match SharedMemory::open(&format!("{ERROR_PREFIX}.{}", JOB_ID.get()), error) {
            Ok(shmem) => Self::Defer(shmem).into(),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => Self::Fatal(format!("failed to open shared memory: {err}")).into(),
        }
    }

    fn deferred_error() -> Option<Self> {
        match SPANK_ERROR.take() {
            err @ Some(_) => err,
            None => Self::open_shmem(None),
        }
    }

    fn log(&self) {
        let err = match self {
            Self::Fatal(ref err) => err.into(),
            Self::Defer(ref shmem) => String::from_utf8_lossy(shmem),
        };
        let msg = CString::new(format!("{ERROR_PREFIX}: {}", err)).unwrap();
        unsafe { spank::slurm_error(c"%s".as_ptr(), msg.as_ptr()) };
    }
}

impl From<SpankError> for c_int {
    fn from(err: SpankError) -> Self {
        match err {
            SpankError::Fatal(_) => {
                err.log();
                spank::SLURM_ERROR as _
            }
            SpankError::Defer(_) => {
                SPANK_ERROR.set(err.into());
                spank::SLURM_SUCCESS as _
            }
        }
    }
}

struct SpankArgs<'a>(HashMap<&'a str, Option<&'a str>>);

impl SpankArgs<'_> {
    fn new<'a>(argc: c_int, argv: *mut *mut c_char) -> SpankArgs<'a> {
        let args = if argc > 0 {
            unsafe {
                slice::from_raw_parts(argv, argc.try_into().unwrap())
                    .iter()
                    .filter_map(|s| {
                        let str = CStr::from_ptr(*s).to_str().ok()?;
                        match str.split_once('=') {
                            kv @ Some(_) => kv.map(|(k, v)| (k, Some(v))),
                            None => Some((str, None)),
                        }
                    })
                    .collect()
            }
        } else {
            HashMap::new()
        };

        SpankArgs(args)
    }

    fn get(&self, opt: &str) -> Option<&str> {
        *self.0.get(opt)?
    }
}

#[no_mangle]
pub extern "C" fn slurm_spank_init(ctx: spank::spank_t, _argc: c_int, _argv: *mut *mut c_char) -> c_int {
    let mut job_id = 0u32;
    let mut job_uid = 0u32;
    let mut step_id = 0u32;

    if let Err(err) = crate::setup_logging() {
        return err.fatal().into();
    }

    match runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => RUNTIME.set(rt),
        Err(err) => return SpankError::Fatal(format!("failed to initialize runtime: {}", err)).into(),
    };

    if unsafe { spank::spank_remote(ctx) == 0 } {
        return spank::SLURM_SUCCESS as _;
    }

    match unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_ID, &mut job_id as *mut u32) } {
        spank::ESPANK_SUCCESS => JOB_ID.set(job_id),
        _ => return SpankError::Fatal("failed to get job ID".into()).into(),
    };

    if unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_UID, &mut job_uid as *mut u32) }
        != spank::ESPANK_SUCCESS
    {
        return SpankError::Fatal("failed to get job UID".into()).into();
    };

    match unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_STEPID, &mut step_id as *mut u32) } {
        spank::ESPANK_SUCCESS if step_id == spank::SLURM_EXTERN_CONT => RUNTIME.with_borrow(|rt| {
            rt.block_on(async {
                ops::fetch_credentials(job_uid)
                    .await
                    .map_or_else(|err| err.defer().into(), |_| spank::SLURM_SUCCESS as _)
            })
        }),
        spank::ESPANK_SUCCESS => spank::SLURM_SUCCESS as _,
        _ => SpankError::Fatal("failed to get jobstep ID".into()).into(),
    }
}

#[no_mangle]
pub extern "C" fn slurm_spank_init_post_opt(_ctx: spank::spank_t, argc: c_int, argv: *mut *mut c_char) -> c_int {
    let min_tkt_lifetime = env::var(ENV_MIN_TKT_LIFETIME)
        .ok()
        .or_else(|| SpankArgs::new(argc, argv).get(OPT_MIN_TKT_LIFETIME).map(String::from));

    match unsafe { spank::spank_context() } {
        spank::spank_context_S_CTX_LOCAL | spank::spank_context_S_CTX_ALLOCATOR => RUNTIME.with_borrow(|rt| {
            rt.block_on(async {
                ops::store_credentials(min_tkt_lifetime.as_deref())
                    .await
                    .map_or_else(|err| err.fatal().into(), |_| spank::SLURM_SUCCESS as _)
            })
        }),
        _ => spank::SLURM_SUCCESS as _,
    }
}

#[no_mangle]
pub extern "C" fn slurm_spank_user_init(_ctx: spank::spank_t, _argc: c_int, _argv: *mut *mut c_char) -> c_int {
    match SpankError::deferred_error() {
        Some(err) => {
            err.log();
            err.into()
        }
        None => spank::SLURM_SUCCESS as _,
    }
}

#[no_mangle]
pub extern "C" fn slurm_spank_task_init(_ctx: spank::spank_t, _argc: c_int, _argv: *mut *mut c_char) -> c_int {
    match SPANK_ERROR.take() {
        Some(_) => spank::SLURM_ERROR as _,
        None => spank::SLURM_SUCCESS as _,
    }
}

#[no_mangle]
pub extern "C" fn slurm_spank_exit(ctx: spank::spank_t, _argc: c_int, _argv: *mut *mut c_char) -> c_int {
    let mut step_id = 0u32;

    if unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_STEPID, &mut step_id as *mut u32) }
        == spank::ESPANK_SUCCESS
        && step_id == spank::SLURM_EXTERN_CONT
    {
        RUNTIME.with_borrow(|rt| rt.block_on(async { ops::terminate().await }));
    }

    SPANK_ERROR.take();
    spank::SLURM_SUCCESS as _
}
