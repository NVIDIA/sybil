/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{
    error::Error,
    fmt::{Debug, Display, Write},
};

pub trait DisplayOptExt {
    fn display<'a>(&'a self) -> Box<dyn tracing::Value + 'a>;
}

impl<T: Display> DisplayOptExt for Option<T> {
    fn display(&self) -> Box<dyn tracing::Value + '_> {
        match self.as_ref() {
            Some(v) => Box::new(tracing::field::display(v)),
            None => Box::new(tracing::field::Empty),
        }
    }
}

pub trait DebugOptExt {
    fn debug<'a>(&'a self) -> Box<dyn tracing::Value + 'a>;
}

impl<T: Debug> DebugOptExt for Option<T> {
    fn debug(&self) -> Box<dyn tracing::Value + '_> {
        match self.as_ref() {
            Some(v) => Box::new(tracing::field::debug(v)),
            None => Box::new(tracing::field::Empty),
        }
    }
}

pub trait ErrorChainExt {
    fn chain(&self) -> impl tracing::Value;
}

impl<T: Error + ?Sized> ErrorChainExt for T {
    fn chain(&self) -> impl tracing::Value {
        let mut err = String::new();
        let mut src = self.source();

        write!(err, "{}", self).ok();
        while let Some(s) = src {
            write!(err, ": {}", s).ok();
            src = s.source();
        }
        err
    }
}
