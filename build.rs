/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{
    env, fs,
    path::{Path, PathBuf},
};

const SYBIL_ADMIN_PRINCIPAL: &str = "sybil/admin";
const SLURM_BASE_URL: &str = "https://raw.githubusercontent.com/SchedMD/slurm/refs/heads";

fn generate_spank_bindings(out_dir: &Path) {
    println!("cargo:rerun-if-env-changed=SLURM_VERSION");

    let (major, minor, branch) = env::var("SLURM_VERSION")
        .map(|v| {
            let (maj, min) = v.split_once('.').expect("malformed SLURM_VERSION");
            (
                maj.parse().unwrap_or(0),
                min.parse().unwrap_or(0),
                "slurm-".to_owned() + &v,
            )
        })
        .unwrap_or((0, 0, "master".to_owned()));

    let mut paths = Vec::new();

    for file in [
        "slurm/slurm.h",
        "slurm/spank.h",
        "slurm/slurm_errno.h",
        "slurm/slurm_version.h.in",
    ] {
        let url = format!("{SLURM_BASE_URL}/{branch}/{file}");
        let body = reqwest::blocking::get(url)
            .and_then(|r| r.text())
            .expect("failed to fetch spank header");

        let path = out_dir.join(file).with_extension("").with_extension("h");
        let header = body.replace(
            "#undef SLURM_VERSION_NUMBER",
            &format!("#define SLURM_VERSION_NUMBER 0x{:02x}{:02x}00", major, minor),
        );
        fs::create_dir_all(path.parent().unwrap()).expect("failed to create spank directory");
        fs::write(&path, &header).expect("failed to write spank header");

        paths.push(path.to_string_lossy().into_owned());
    }

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-F{}", out_dir.display()))
        .headers(&paths)
        .generate_comments(false)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .wrap_unsafe_ops(true)
        .generate()
        .expect("failed to generate spank bindings");

    bindings
        .write_to_file(out_dir.join("spank.rs"))
        .expect("failed to write spank bindings");
}

fn main() {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    println!("cargo:rerun-if-changed=src/krb");
    println!("cargo:rustc-link-search=native={}", out_dir.display());

    let bindings = bindgen::Builder::default()
        .header("src/krb/krbutil.h")
        .generate_comments(false)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("krb5_data")
        .allowlist_type("krb5_principal")
        .allowlist_type("krb5_ticket_times")
        .allowlist_function("krb5_copy_data")
        .allowlist_function("krb5_free_data")
        .allowlist_function("krb5_free_principal")
        .allowlist_function("krb5_unparse_name")
        .allowlist_function("krb5_free_unparsed_name")
        .allowlist_function("krb5_get_default_realm")
        .allowlist_function("krb5_cc_default_name")
        .allowlist_function("krb5_free_default_realm")
        .allowlist_function("krb5_free_data_contents")
        .allowlist_function("krb5_get_error_message")
        .allowlist_function("krb5_free_error_message")
        .allowlist_function("krbutil_.*")
        .allowlist_var("KRB5_TGS_NAME")
        .allowlist_var("KRB5_ANONYMOUS_REALMSTR")
        .allowlist_var("KRB5_ERR_INVALID_UTF8")
        .allowlist_var("KRB5KRB_AP_ERR_TKT_EXPIRED")
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
        .define("KRBUTIL_CLIENT", "1")
        .cargo_metadata(false)
        .compile("krbutil_clnt");

    for flag in [
        "-Wl,-Bstatic",
        "-lkrbutil_clnt",
        "-Wl,-Bdynamic",
        "-lkrb5",
        "-lk5crypto",
    ] {
        println!("cargo:rustc-link-arg-bin=sybil={}", flag);
    }

    cc::Build::new()
        .file("src/krb/krbutil.c")
        .warnings(true)
        .extra_warnings(true)
        .flag("-std=c99")
        .flag("-D_DEFAULT_SOURCE")
        .flag("-D_FORTIFY_SOURCE=2")
        .flag("-fstack-protector")
        .define("KRBUTIL_SERVER", "1")
        .define("KADMIN_PRINCIPAL", SYBIL_ADMIN_PRINCIPAL)
        .cargo_metadata(false)
        .compile("krbutil_serv");

    for flag in [
        "-Wl,-Bstatic",
        "-lkrbutil_serv",
        "-Wl,-Bdynamic",
        "-lkrb5",
        "-lk5crypto",
        "-lkadm5srv",
    ] {
        println!("cargo:rustc-link-arg-bin=sybild={}", flag);
    }

    if cfg!(feature = "slurm") {
        generate_spank_bindings(&out_dir);

        for flag in [
            "-Wl,-Bstatic",
            "-lkrbutil_clnt",
            "-Wl,-Bdynamic",
            "-lkrb5",
            "-lk5crypto",
        ] {
            println!("cargo:rustc-cdylib-link-arg={}", flag);
        }
    }
}
