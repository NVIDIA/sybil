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

const OPT_FORWARD_CREDS: &str = "default";
const ENV_FORWARD_CREDS: &str = "SYBIL_SPANK_KERBEROS";
const ENV_REQUIRE_CREDS: &CStr = c"SYBIL_SPANK_KERBEROS_ENABLED";
const OPT_MIN_TKT_LIFETIME: &str = "min_tkt_lifetime";

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

enum ForwardCredsOpt {
    Yes,
    No,
    Auto,
    Force,
}

impl ForwardCredsOpt {
    fn register(ctx: spank::spank_t) -> Result<(), SpankError> {
        let mut opt = spank::spank_option {
            name: c"kerberos".as_ptr() as _,
            arginfo: c"[yes|no|auto|force]".as_ptr() as _,
            usage: c"[sybil] forward kerberos credentials to the allocated nodes".as_ptr() as _,
            has_arg: 1,
            val: 0,
            cb: Some(Self::callback),
        };
        match unsafe { spank::spank_option_register(ctx, &mut opt) } {
            spank::ESPANK_SUCCESS => Ok(()),
            _ => Err(SpankError::Fatal("failed to register command line option".into())),
        }
    }

    extern "C" fn callback(_val: c_int, opt: *const c_char, _remote: c_int) -> c_int {
        match unsafe { CStr::from_ptr(opt).to_string_lossy().as_ref() } {
            "yes" | "no" | "auto" | "force" => spank::SLURM_SUCCESS as _,
            _ => spank::SLURM_ERROR as _,
        }
    }

    fn from_env(args: &SpankArgs) -> Self {
        match env::var("_SLURM_SPANK_OPTION_sybil_kerberos")
            .ok()
            .or_else(|| env::var(ENV_FORWARD_CREDS).ok())
            .as_deref()
            .or_else(|| args.get(OPT_FORWARD_CREDS))
        {
            Some("yes") => Self::Yes,
            Some("auto") => Self::Auto,
            Some("force") => Self::Force,
            Some("no") | Some(_) | None => Self::No,
        }
    }
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

    if let Err(err) = ForwardCredsOpt::register(ctx) {
        return err.into();
    }

    if unsafe { spank::spank_remote(ctx) == 0 } {
        return spank::SLURM_SUCCESS as _;
    }

    match unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_ID, &mut job_id) } {
        spank::ESPANK_SUCCESS => JOB_ID.set(job_id),
        _ => return SpankError::Fatal("failed to get job ID".into()).into(),
    };
    if unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_UID, &mut job_uid) } != spank::ESPANK_SUCCESS {
        return SpankError::Fatal("failed to get job UID".into()).into();
    }
    if unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_STEPID, &mut step_id) } != spank::ESPANK_SUCCESS {
        return SpankError::Fatal("failed to get jobstep ID".into()).into();
    }

    if step_id != spank::SLURM_EXTERN_CONT {
        return spank::SLURM_SUCCESS as _;
    }

    RUNTIME.with_borrow(|rt| {
        rt.block_on(async {
            ops::fetch_credentials(job_uid)
                .await
                .map_or_else(|err| err.defer().into(), |_| spank::SLURM_SUCCESS as _)
        })
    })
}

#[no_mangle]
pub extern "C" fn slurm_spank_init_post_opt(_ctx: spank::spank_t, argc: c_int, argv: *mut *mut c_char) -> c_int {
    match unsafe { spank::spank_context() } {
        spank::spank_context_S_CTX_LOCAL | spank::spank_context_S_CTX_ALLOCATOR => (),
        _ => return spank::SLURM_SUCCESS as _,
    };

    let require_creds = ENV_REQUIRE_CREDS.to_str().unwrap();
    if env::var(require_creds).is_ok() {
        return spank::SLURM_SUCCESS as _;
    }

    let args = SpankArgs::new(argc, argv);
    let forward = ForwardCredsOpt::from_env(&args);
    let lifetime = args.get(OPT_MIN_TKT_LIFETIME);

    match forward {
        ForwardCredsOpt::Yes => {
            env::set_var(require_creds, "1");
            if let Err(err) = ops::check_credentials(lifetime) {
                return err.fatal().into();
            }
        }
        ForwardCredsOpt::No => {
            env::set_var(require_creds, "0");
            return spank::SLURM_SUCCESS as _;
        }
        ForwardCredsOpt::Auto => {
            if ops::check_credentials(lifetime).is_ok() {
                env::set_var(require_creds, "1");
            } else {
                env::set_var(require_creds, "0");
                return spank::SLURM_SUCCESS as _;
            }
        }
        ForwardCredsOpt::Force => env::set_var(require_creds, "1"),
    };

    RUNTIME.with_borrow(|rt| {
        rt.block_on(async {
            ops::store_credentials()
                .await
                .map_or_else(|err| err.fatal().into(), |_| spank::SLURM_SUCCESS as _)
        })
    })
}

#[no_mangle]
pub extern "C" fn slurm_spank_user_init(ctx: spank::spank_t, _argc: c_int, _argv: *mut *mut c_char) -> c_int {
    let mut require_creds = [0u8; 2];

    unsafe {
        spank::spank_getenv(
            ctx,
            ENV_REQUIRE_CREDS.as_ptr(),
            require_creds.as_mut_ptr() as _,
            require_creds.len() as _,
        )
    };

    match SpankError::deferred_error() {
        Some(err) if require_creds[0] == b'1' => {
            err.log();
            err.into()
        }
        _ => spank::SLURM_SUCCESS as _,
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

    SPANK_ERROR.set(None);

    if unsafe { spank::spank_remote(ctx) == 0 } {
        return spank::SLURM_SUCCESS as _;
    }

    if unsafe { spank::spank_get_item(ctx, spank::spank_item_S_JOB_STEPID, &mut step_id) } != spank::ESPANK_SUCCESS {
        return SpankError::Fatal("failed to get jobstep ID".into()).into();
    }

    if step_id == spank::SLURM_EXTERN_CONT {
        RUNTIME.with_borrow(|rt| rt.block_on(async { ops::cleanup().await }));
    }
    spank::SLURM_SUCCESS as _
}
