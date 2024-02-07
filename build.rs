/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{env, path::PathBuf};

const SYBIL_ADMIN_PRINCIPAL: &str = "sybil/admin";

fn main() {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    println!("cargo:rerun-if-changed=src/krb");

    let bindings = bindgen::Builder::default()
        .header("src/krb/krbutil.h")
        .generate_comments(false)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("krb5_data")
        .allowlist_function("krb5_get_default_realm")
        .allowlist_function("krb5_free_default_realm")
        .allowlist_function("krb5_free_data_contents")
        .allowlist_function("krb5_get_error_message")
        .allowlist_function("krb5_free_error_message")
        .allowlist_function("krbutil_.*")
        .allowlist_var("KRB5_TGS_NAME")
        .allowlist_var("KRB5_ERR_INVALID_UTF8")
        .allowlist_var("KRB5_CC_IO")
        .allowlist_var("KV5M_DATA")
        .generate()
        .expect("failed to generate krbutil bindings");

    bindings
        .write_to_file(out_dir.join("krbutil.rs"))
        .expect("failed to write krbutil bindings");

    cc::Build::new()
        .file("src/krb/krbutil.c")
        .warnings(true)
        .extra_warnings(true)
        .flag("-std=c99")
        .flag("-D_DEFAULT_SOURCE")
        .flag("-D_FORTIFY_SOURCE=2")
        .flag("-fstack-protector")
        .define("KADMIN_PRINCIPAL", SYBIL_ADMIN_PRINCIPAL)
        .compile("krbutil");

    for (bin, sym) in [("sybil", "krbutil_init_krb5"), ("sybild", "krbutil_init_kadm5")] {
        println!("cargo:rustc-link-arg-bin={bin}=-Wl,--defsym=krbutil_init={sym}");
    }
    for lib in ["krb5", "kadm5srv", "k5crypto", "krb5support"] {
        println!("cargo:rustc-link-lib={lib}");
    }
}
