/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <krb5/krb5.h>
extern krb5_error_code krb5_encrypt_tkt_part(krb5_context, const krb5_keyblock *, krb5_ticket *);
extern krb5_error_code encode_krb5_ticket(const krb5_ticket *, krb5_data **);

krb5_error_code krbutil_init(void);
void krbutil_fini(void);
krb5_context krbutil_context(void);
krb5_error_code krbutil_forge_creds(krb5_context, krb5_data **, const char *, const char *, const char *,
                                    const char *, const char *, const char *, const char *)
                                    __attribute__((nonnull(2,3,4,5,6)));
krb5_error_code krbutil_local_user(krb5_context, char *, size_t, const char *)  __attribute__((nonnull(2,4)));
krb5_error_code krbutil_local_user_creds(krb5_context, char *, size_t, const krb5_data *)  __attribute__((nonnull(2,4)));
krb5_error_code krbutil_store_creds(krb5_context, const krb5_data *) __attribute__((nonnull(2)));
