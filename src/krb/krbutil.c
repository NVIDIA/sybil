/*
 * SPDX-FileCopyrightText: Copyright (c) 2023, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <kadm5/admin.h>

#include "krbutil.h"

#define string(x) #x
#define goto_out(ret, ...) if (ret) goto out##__VA_OPT__(_)##__VA_ARGS__

static krb5_context context = NULL;
static void *kadmin = NULL;

__attribute__((constructor))
static void krbutil_ctor(void)
{
        krb5_error_code ret;

        if ((ret = krbutil_init())) {
                const char *errmsg = krb5_get_error_message(context, ret);
                fprintf(stderr, "%s\n", context ? errmsg : "Could not initialize krb5 context");
                krb5_free_error_message(context, errmsg);
                exit(1);
        }
}

__attribute__((destructor))
static void krbutil_dtor(void)
{
        krbutil_fini();
}

krb5_error_code krbutil_init_krb5(void)
{
        return (krb5_init_context(&context));
}

krb5_error_code krbutil_init_kadm5(void)
{
        kadm5_ret_t ret;
        char *realm;

        ret = kadm5_init_krb5_context(&context);
        goto_out(ret);
        ret = krb5_get_default_realm(context, &realm);
        goto_out(ret);
        ret = kadm5_init(context, string(KADMIN_PRINCIPAL), NULL, NULL,
                         &(kadm5_config_params){.mask = KADM5_CONFIG_REALM, .realm = realm},
                         KADM5_STRUCT_VERSION, KADM5_API_VERSION_4, NULL, &kadmin);

        krb5_free_default_realm(context, realm);
out:
        return (krb5_error_code)(ret);
}

void krbutil_fini(void)
{
        if (context != NULL)
                krb5_free_context(context);
        if (kadmin != NULL)
                kadm5_destroy(kadmin);
}

krb5_context krbutil_context(void)
{
        return (context);
}

static krb5_error_code set_ticket_flags(const char *str,
                                        krb5_flags *flags)
{
        const struct { char c; krb5_flags flag; } map[] = {
                {'A', TKT_FLG_PRE_AUTH},
                {'D', TKT_FLG_MAY_POSTDATE},
                {'d', TKT_FLG_POSTDATED},
                {'F', TKT_FLG_FORWARDABLE},
                {'f', TKT_FLG_FORWARDED},
                {'H', TKT_FLG_HW_AUTH},
                {'I', TKT_FLG_INITIAL},
                {'i', TKT_FLG_INVALID},
                {'P', TKT_FLG_PROXIABLE},
                {'p', TKT_FLG_PROXY},
                {'R', TKT_FLG_RENEWABLE},
        };

        for (*flags = 0; *str != '\0'; ++str) {
                bool found = false;
                for (size_t i = 0; sizeof(map) / sizeof(*map); ++i) {
                        if (*str == map[i].c) {
                                found = true;
                                *flags |= map[i].flag;
                                break;
                        }
                }
                if (!found)
                        return (KRB5_INVALID_FLAGS);
        }
        return (0);
}

static krb5_error_code parse_time(const char *str,
                                  krb5_timestamp now,
                                  krb5_timestamp *time)
{
        krb5_error_code ret;
        krb5_deltat delta;

        if (str == NULL) {
                *time = now;
                return (0);
        }

        ret = krb5_string_to_deltat((char *)str, &delta);
        if (ret || delta == 0) {
                ret = krb5_string_to_timestamp((char *)str, time);
                if (ret || *time == 0)
                        return (ret ? ret : KRB5_DELTAT_BADFORMAT);
        } else
                *time = now + delta;
        return (0);
}

static krb5_error_code set_ticket_times(krb5_context ctx,
                                        const char *start,
                                        const char *end,
                                        const char *renew,
                                        krb5_ticket_times *times)
{
        krb5_error_code ret;
        krb5_timestamp now;

        ret = krb5_timeofday(ctx, &now);
        goto_out(ret);

        ret = parse_time(start, now, &times->starttime);
        goto_out(ret);
        ret = parse_time(end, now, &times->endtime);
        goto_out(ret);
        ret = parse_time(renew, now, &times->renew_till);
        goto_out(ret);

        times->authtime = times->starttime;
out:
        return (ret);
}

static krb5_error_code encrypt_ticket(krb5_context ctx,
                                      krb5_principal serv,
                                      krb5_enctype enc,
                                      krb5_ticket *tkt)
{
        kadm5_ret_t ret;
        kadm5_key_data *keys;
        int i, nkeys;

        ret = kadm5_get_principal_keys(kadmin, serv, 0, &keys, &nkeys);
        goto_out(ret, keys);

        for (i = 0; i < nkeys && enc != keys[i].key.enctype; ++i);
        if (i == nkeys)
                ret = KRB5_BAD_ENCTYPE;
        else {
                tkt->enc_part.kvno = keys[i].kvno;
                ret = krb5_encrypt_tkt_part(ctx, &keys[i].key, tkt);
        }

        for (i = 0; i < nkeys; ++i)
                explicit_bzero(keys[i].key.contents, keys[i].key.length);
        kadm5_free_kadm5_key_data(ctx, nkeys, keys);
out_keys:
        return (krb5_error_code)(ret);
}

static krb5_error_code encode_credentials(krb5_context ctx,
                                          const krb5_ticket *tkt,
                                          krb5_data *creds)
{
        krb5_error_code ret;
        krb5_data *ticket;

        ret = encode_krb5_ticket(tkt, &ticket);
        goto_out(ret, ticket);

        krb5_creds cred = {
                .magic = KV5M_CREDS,
                .client = tkt->enc_part2->client,
                .server = tkt->server,
                .keyblock = *tkt->enc_part2->session,
                .times = tkt->enc_part2->times,
                .is_skey = false,
                .ticket_flags = tkt->enc_part2->flags,
                .addresses = tkt->enc_part2->caddrs,
                .authdata = tkt->enc_part2->authorization_data,
                .ticket = *ticket,
        };
        // FIXME: Replace with krb5_marshal_credentials once we move to libkrb5 1.20.
        //ret = krb5_marshal_credentials(ctx, &cred, creds);
        struct k5buf buf;
        k5_buf_init_dynamic(&buf);
        k5_marshal_cred(&buf, 4, &cred);
        ret = k5_buf_status(&buf);
        goto_out(ret, buf);
        *creds = (krb5_data){
                .magic = KV5M_DATA,
                .data = buf.data,
                .length = buf.len,
        };

out_buf:
        explicit_bzero(ticket->data, ticket->length);
        krb5_free_data(ctx, ticket);
out_ticket:
        return (ret);
}

krb5_error_code krbutil_forge_creds(krb5_context ctx,
                                    krb5_data *creds,
                                    const char *clnt_princ,
                                    const char *serv_princ,
                                    const char *enc_type,
                                    const char *tkt_flags,
                                    const char *start_time,
                                    const char *end_time,
                                    const char *renew_till)
{
        krb5_error_code ret;
        krb5_enctype enc;
        krb5_flags flags;
        krb5_ticket_times times;
        krb5_principal clnt, serv;
        krb5_keyblock skey;

        if (*clnt_princ == '\0' || *serv_princ == '\0')
                return (KRB5_PARSE_MALFORMED);

        ret = krb5_string_to_enctype((char *)enc_type, &enc);
        goto_out(ret);
        ret = set_ticket_flags(tkt_flags, &flags);
        goto_out(ret);
        ret = set_ticket_times(ctx, start_time, end_time, renew_till, &times);
        goto_out(ret);
        ret = krb5_parse_name_flags(ctx, clnt_princ, KRB5_PRINCIPAL_PARSE_ENTERPRISE, &clnt);
        goto_out(ret, clnt);
        ret = krb5_parse_name(ctx, serv_princ, &serv);
        goto_out(ret, serv);
        ret = krb5_c_make_random_key(ctx, enc, &skey);
        goto_out(ret, skey);

        krb5_ticket tkt = {
                .magic = KV5M_TICKET,
                .server = serv,
                .enc_part = {
                        .magic = KV5M_ENC_DATA,
                        .enctype = enc,
                },
                .enc_part2 = &(krb5_enc_tkt_part) {
                        .magic = KV5M_ENC_TKT_PART,
                        .flags = flags,
                        .session = &skey,
                        .client = clnt,
                        .transited = {
                                .magic = KV5M_TRANSITED,
                                .tr_type = KRB5_DOMAIN_X500_COMPRESS,
                                .tr_contents = {0},
                        },
                        .times = times,
                        .caddrs = NULL,
                        .authorization_data = NULL,
                }
        };
        ret = encrypt_ticket(ctx, serv, enc, &tkt);
        goto_out(ret, tkt);

        ret = encode_credentials(ctx, &tkt, creds);

        explicit_bzero(tkt.enc_part.ciphertext.data, tkt.enc_part.ciphertext.length);
        krb5_free_data_contents(ctx, &tkt.enc_part.ciphertext);
out_tkt:
        explicit_bzero(skey.contents, skey.length);
        krb5_free_keyblock_contents(ctx, &skey);
out_skey:
        krb5_free_principal(ctx, serv);
out_serv:
        krb5_free_principal(ctx, clnt);
out_clnt:
out:
        return (ret);
}

krb5_error_code krbutil_local_user(krb5_context ctx, char *user, size_t size, const char *user_princ)
{
        krb5_error_code ret;
        krb5_principal princ;

        if (*user_princ == '\0')
                return (KRB5_PARSE_MALFORMED);

        ret = krb5_parse_name_flags(ctx, user_princ, KRB5_PRINCIPAL_PARSE_ENTERPRISE, &princ);
        goto_out(ret, princ);
        ret = krb5_aname_to_localname(ctx, princ, size, user);

        krb5_free_principal(ctx, princ);
out_princ:
        return (ret);
}

krb5_error_code krbutil_local_user_creds(krb5_context ctx, char *user, size_t size, const krb5_data *cred_data)
{
        krb5_error_code ret;
        krb5_creds creds;

        ret = k5_unmarshal_cred(cred_data->data, cred_data->length, 4, &creds);
        goto_out(ret, creds);
        ret = krb5_aname_to_localname(ctx, creds.client, size, user);

        explicit_bzero(creds.ticket.data, creds.ticket.length);
        explicit_bzero(creds.keyblock.contents, creds.keyblock.length);
        krb5_free_cred_contents(ctx, &creds);
out_creds:
        return (ret);
}

krb5_error_code krbutil_store_creds(krb5_context ctx, const krb5_data *cred_data)
{
        krb5_error_code ret;
        krb5_ccache ccache;
        krb5_creds creds;

        ret = krb5_cc_default(ctx, &ccache);
        goto_out(ret, ccache);
        ret = k5_unmarshal_cred(cred_data->data, cred_data->length, 4, &creds);
        goto_out(ret, creds);
        ret = krb5_cc_initialize(ctx, ccache, creds.client);
        goto_out(ret, init);
        ret = krb5_cc_store_cred(ctx, ccache, &creds);

out_init:
        explicit_bzero(creds.ticket.data, creds.ticket.length);
        explicit_bzero(creds.keyblock.contents, creds.keyblock.length);
        krb5_free_cred_contents(ctx, &creds);
out_creds:
        krb5_cc_close(ctx, ccache);
out_ccache:
        return (ret);
}
