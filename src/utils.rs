/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{ffi::CStr, fmt};

pub trait DisplayOptExt {
    fn display<'a>(&'a self) -> Box<dyn tracing::Value + 'a>;
}

impl<T: fmt::Display> DisplayOptExt for Option<T> {
    fn display(&self) -> Box<dyn tracing::Value + '_> {
        if self.is_some() {
            Box::new(tracing::field::display(self.as_ref().unwrap()))
        } else {
            Box::new(tracing::field::Empty)
        }
    }
}

pub trait DebugOptExt {
    fn debug<'a>(&'a self) -> Box<dyn tracing::Value + 'a>;
}

impl<T: fmt::Debug> DebugOptExt for Option<T> {
    fn debug(&self) -> Box<dyn tracing::Value + '_> {
        if self.is_some() {
            Box::new(tracing::field::debug(self.as_ref().unwrap()))
        } else {
            Box::new(tracing::field::Empty)
        }
    }
}

pub const fn const_cstr(cstr: &[u8]) -> &str {
    match unsafe { CStr::from_bytes_with_nul_unchecked(cstr).to_str() } {
        Ok(s) => s,
        Err(_) => panic!("invalid UTF-8 in C string"),
    }
}
