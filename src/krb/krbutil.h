/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <krb5/krb5.h>
extern krb5_error_code krb5_encrypt_tkt_part(krb5_context, const krb5_keyblock *, krb5_ticket *);
extern krb5_error_code encode_krb5_ticket(const krb5_ticket *, krb5_data **);
extern krb5_error_code krb5_get_cred_via_tkt(krb5_context, krb5_creds *, krb5_flags, krb5_address * const *, krb5_creds *, krb5_creds **);

krb5_error_code krbutil_init(void);
void krbutil_fini(void);
krb5_context krbutil_context(void);
krb5_error_code krbutil_forge_creds(krb5_context, krb5_data **, const char *, const char *, const char *,
                                    const char *, const char *, const char *, const char *)
                                    __attribute__((nonnull(2,3,4,5,6)));
krb5_error_code krbutil_local_user(krb5_context, char *, size_t, const char *)  __attribute__((nonnull(2,4)));
krb5_error_code krbutil_local_user_creds(krb5_context, char *, size_t, const krb5_data *)  __attribute__((nonnull(2,4)));
krb5_error_code krbutil_info_creds(krb5_context, krb5_principal *, krb5_ticket_times *, const krb5_data *)  __attribute__((nonnull(2,3,4)));
krb5_error_code krbutil_lasting_creds(krb5_context, const char *, bool *, const krb5_data *)  __attribute__((nonnull(2,3,4)));
krb5_error_code krbutil_store_creds(krb5_context, const krb5_data *) __attribute__((nonnull(2)));
krb5_error_code krbutil_fetch_creds(krb5_context, krb5_data **, const char *, const char *, bool) __attribute__((nonnull(3)));
krb5_error_code krbutil_destroy_all_ccaches(krb5_context);
