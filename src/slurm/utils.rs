/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use nix::{
    fcntl::OFlag,
    sys::{
        mman::{self, MapFlags, ProtFlags},
        stat::{self, Mode},
    },
    unistd,
};
use std::{
    io::Error as IOError,
    ops::Deref,
    os::{fd::AsRawFd, raw::c_void},
    ptr::{self, NonNull},
    slice,
};

pub const fn cargo_package_version() -> u32 {
    match (
        u32::from_str_radix(env!("CARGO_PKG_VERSION_MAJOR"), 10),
        u32::from_str_radix(env!("CARGO_PKG_VERSION_MINOR"), 10),
        u32::from_str_radix(env!("CARGO_PKG_VERSION_PATCH"), 10),
    ) {
        (Ok(maj), Ok(min), Ok(patch)) => (maj << 16) | (min << 8) | patch,
        _ => panic!("invalid package version"),
    }
}

pub struct SharedMemory {
    name: Option<String>,
    addr: NonNull<c_void>,
    size: usize,
}

impl SharedMemory {
    pub fn open(name: &str, data: Option<&[u8]>) -> Result<SharedMemory, IOError> {
        let flags = if data.is_some() {
            OFlag::O_CREAT | OFlag::O_RDWR
        } else {
            OFlag::O_RDONLY
        };
        let fd = mman::shm_open(
            name,
            flags,
            Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH,
        )?;

        let size = match data {
            Some(data) => {
                unistd::ftruncate(&fd, data.len().try_into().unwrap())?;
                data.len()
            }
            None => stat::fstat(fd.as_raw_fd())?.st_size as _,
        };

        let flags = if data.is_some() {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            ProtFlags::PROT_READ
        };
        let addr = unsafe { mman::mmap(None, size.try_into().unwrap(), flags, MapFlags::MAP_SHARED, fd, 0) }?;

        if let Some(data) = data {
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), addr.as_ptr() as _, size) };
        }
        Ok(SharedMemory {
            name: data.and(Some(name.into())),
            addr,
            size,
        })
    }
}

impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.addr.as_ptr() as _, self.size) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe { mman::munmap(self.addr, self.size).ok() };
        if let Some(name) = self.name.as_deref() {
            mman::shm_unlink(name).ok();
        }
    }
}
