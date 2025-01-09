/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025, NVIDIA CORPORATION. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <grp.h>
#include <pthread.h>
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

static void *kadmin = NULL;
static pthread_mutex_t kadmin_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef KRBUTIL_SERVER

krb5_context krbutil_context(void)
{
        krb5_context ctx;

        return (kadm5_init_krb5_context(&ctx) ? NULL : ctx);
}

static krb5_error_code kadmin_init_lazy(void)
{
        krb5_context ctx;
        kadm5_ret_t ret;

        if (kadmin != NULL)
                return (0);

        ctx = krbutil_context();
        ret = kadm5_init(ctx, string(KADMIN_PRINCIPAL), NULL, NULL, NULL,
                         KADM5_STRUCT_VERSION, KADM5_API_VERSION_4, NULL, &kadmin);
        return (ret);
}

__attribute__((destructor))
static void kadmin_fini(void)
{
        if (kadmin != NULL)
                kadm5_destroy(kadmin);
}

#elif KRBUTIL_CLIENT

krb5_context krbutil_context(void)
{
        krb5_context ctx;

        return (krb5_init_context(&ctx) ? NULL : ctx);
}

static krb5_error_code kadmin_init_lazy(void)
{
        return (KRB5KDC_ERR_NONE);
}

#endif

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
                *time = (krb5_timestamp)((uint32_t)now + (uint32_t)delta);
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

        pthread_mutex_lock(&kadmin_lock);
        if ((ret = kadmin_init_lazy()) == 0) // XXX: Prevent leak by initializing kadm5 once.
                ret = kadm5_get_principal_keys(kadmin, serv, 0, &keys, &nkeys);
        pthread_mutex_unlock(&kadmin_lock);
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

static krb5_error_code encode_ticket(krb5_context ctx,
                                     const krb5_ticket *tkt,
                                     krb5_data **cred_data)
{
        krb5_error_code ret;
        krb5_data *ticket;
        krb5_auth_context auth;

        ret = encode_krb5_ticket(tkt, &ticket);
        goto_out(ret, ticket);

        krb5_creds creds = {
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
        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_mk_1cred(ctx, auth, &creds, cred_data, NULL);

        krb5_auth_con_free(ctx, auth);
out_auth:
        explicit_bzero(ticket->data, ticket->length);
        krb5_free_data(ctx, ticket);
out_ticket:
        return (ret);
}

krb5_error_code krbutil_forge_creds(krb5_context ctx,
                                    krb5_data **cred_data,
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

        ret = encode_ticket(ctx, &tkt, cred_data);

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
        krb5_auth_context auth;
        krb5_creds **creds;

        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_rd_cred(ctx, auth, (krb5_data *)cred_data, &creds, NULL);
        goto_out(ret, creds);

        ret = krb5_aname_to_localname(ctx, creds[0]->client, size, user);

        for (size_t i = 0; creds[i] != NULL; ++i) {
                explicit_bzero(creds[i]->ticket.data, creds[i]->ticket.length);
                explicit_bzero(creds[i]->keyblock.contents, creds[i]->keyblock.length);
        }
        krb5_free_tgt_creds(ctx, creds);
out_creds:
        krb5_auth_con_free(ctx, auth);
out_auth:
        return (ret);
}

krb5_error_code krbutil_lifetime_creds(krb5_context ctx, time_t *lifetime, const krb5_data *cred_data)
{
        krb5_error_code ret;
        krb5_auth_context auth;
        krb5_creds **creds;

        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_rd_cred(ctx, auth, (krb5_data *)cred_data, &creds, NULL);
        goto_out(ret, creds);

        *lifetime = (time_t)(uint32_t)creds[0]->times.endtime;

        for (size_t i = 0; creds[i] != NULL; ++i) {
                explicit_bzero(creds[i]->ticket.data, creds[i]->ticket.length);
                explicit_bzero(creds[i]->keyblock.contents, creds[i]->keyblock.length);
        }
        krb5_free_tgt_creds(ctx, creds);
out_creds:
        krb5_auth_con_free(ctx, auth);
out_auth:
        return (ret);
}

krb5_error_code krbutil_lasting_creds(krb5_context ctx, const char *lifetime, bool *will_last, const krb5_data *cred_data)
{
        krb5_error_code ret;
        krb5_timestamp now;
        krb5_timestamp deadline;
        krb5_auth_context auth;
        krb5_creds **creds;

        ret = krb5_timeofday(ctx, &now);
        goto_out(ret);
        ret = parse_time(lifetime, now, &deadline);
        goto_out(ret);

        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_rd_cred(ctx, auth, (krb5_data *)cred_data, &creds, NULL);
        goto_out(ret, creds);

        if ((uint32_t)creds[0]->times.renew_till >= (uint32_t)deadline)
                *will_last = true;
        else
                *will_last = false;

        for (size_t i = 0; creds[i] != NULL; ++i) {
                explicit_bzero(creds[i]->ticket.data, creds[i]->ticket.length);
                explicit_bzero(creds[i]->keyblock.contents, creds[i]->keyblock.length);
        }
        krb5_free_tgt_creds(ctx, creds);
out_creds:
        krb5_auth_con_free(ctx, auth);
out_auth:
out:
        return (ret);
}

krb5_error_code krbutil_store_creds(krb5_context ctx, const krb5_data *cred_data)
{
        krb5_error_code ret;
        krb5_auth_context auth;
        krb5_ccache ccache, ccache_mem;
        krb5_creds **creds;

        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_rd_cred(ctx, auth, (krb5_data *)cred_data, &creds, NULL);
        goto_out(ret, creds);

        ret = krb5_cc_default(ctx, &ccache);
        goto_out(ret, ccache);
        ret = krb5_cc_new_unique(ctx, "MEMORY", NULL, &ccache_mem);
        goto_out(ret, ccache_mem);
        ret = krb5_cc_initialize(ctx, ccache_mem, creds[0]->client);
        goto_out(ret, init);
        for (size_t i = 0; creds[i] != NULL; ++i) {
                ret = krb5_cc_store_cred(ctx, ccache_mem, creds[i]);
                goto_out(ret, init);
        }
        ret = krb5_cc_move(ctx, ccache_mem, ccache);
        goto_out(ret, init);
        goto out_ccache_mem;

out_init:
        krb5_cc_destroy(ctx, ccache_mem);
out_ccache_mem:
        krb5_cc_close(ctx, ccache);
out_ccache:
        for (size_t i = 0; creds[i] != NULL; ++i) {
                explicit_bzero(creds[i]->ticket.data, creds[i]->ticket.length);
                explicit_bzero(creds[i]->keyblock.contents, creds[i]->keyblock.length);
        }
        krb5_free_tgt_creds(ctx, creds);
out_creds:
        krb5_auth_con_free(ctx, auth);
out_auth:
        return (ret);
}

static krb5_error_code fetch_cross_realm_tgt(krb5_context ctx,
                                             krb5_creds **cr_creds,
                                             const char *realm,
                                             const krb5_ccache ccache,
                                             const krb5_creds *tgt,
                                             const char *min_life)
{
        krb5_error_code ret;
        krb5_principal serv;
        krb5_creds creds;
        krb5_flags flags = (tgt->ticket_flags & KDC_TKT_COMMON_MASK) | KDC_OPT_FORWARDED | KDC_OPT_CANONICALIZE;

        ret = krb5_build_principal(ctx, &serv, tgt->client->realm.length, tgt->client->realm.data,
                                   KRB5_TGS_NAME, realm, NULL);
        goto_out(ret, serv);

        krb5_creds query = {
                .magic = KV5M_CREDS,
                .client = tgt->client,
                .server = serv,
        };
        ret = set_ticket_times(ctx, NULL, min_life, min_life, &query.times);
        goto_out(ret, creds);
        ret = krb5_cc_retrieve_cred(ctx, ccache, KRB5_TC_MATCH_TIMES, &query, &creds);
        switch (ret) {
        case 0:
                ret = krb5_copy_creds(ctx, &creds, cr_creds);
                break;
        case KRB5_CC_NOTFOUND:
                memset(&query.times, 0, sizeof(query.times));
                ret = krb5_get_cred_via_tkt(ctx, (krb5_creds *)tgt, flags, NULL, &query, cr_creds);
                goto_out(ret, creds);
                krb5_cc_store_cred(ctx, ccache, *cr_creds);
                __attribute__((fallthrough));
        default:
                goto out_creds;
        };

        explicit_bzero(creds.ticket.data, creds.ticket.length);
        explicit_bzero(creds.keyblock.contents, creds.keyblock.length);
        krb5_free_cred_contents(ctx, &creds);
out_creds:
        krb5_free_principal(ctx, serv);
out_serv:
        return (ret);
}

krb5_error_code krbutil_fetch_creds(krb5_context ctx,
                                    krb5_data **cred_data,
                                    const char *ccname,
                                    const char *min_life,
                                    bool with_crealm)
{
        krb5_error_code ret;
        krb5_ccache ccache;
        krb5_auth_context auth;
        krb5_principal clnt, serv;
        krb5_creds creds, *cr_creds = NULL;
        char *realm;

        if (*ccname == '\0')
                return (KRB5_CC_BADNAME);

        ret = krb5_get_default_realm(ctx, &realm);
        goto_out(ret, realm);
        ret = krb5_cc_resolve(ctx, ccname, &ccache);
        goto_out(ret, ccache);
        ret = krb5_cc_get_principal(ctx, ccache, &clnt);
        goto_out(ret, clnt);
        ret = krb5_build_principal_ext(ctx, &serv, clnt->realm.length, clnt->realm.data,
                                       KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                       clnt->realm.length, clnt->realm.data, NULL);
        goto_out(ret, serv);

        krb5_creds query = {
                .magic = KV5M_CREDS,
                .client = clnt,
                .server = serv,
        };
        ret = set_ticket_times(ctx, NULL, min_life, min_life, &query.times);
        goto_out(ret, creds);
        ret = krb5_cc_retrieve_cred(ctx, ccache, KRB5_TC_MATCH_TIMES, &query, &creds);
        goto_out(ret, creds);

        if (with_crealm && strncmp(realm, clnt->realm.data, clnt->realm.length)) {
                ret = fetch_cross_realm_tgt(ctx, &cr_creds, realm, ccache, &creds, min_life);
                goto_out(ret, cr_creds);
        }

        ret = krb5_auth_con_init(ctx, &auth);
        goto_out(ret, auth);
        krb5_auth_con_setflags(ctx, auth, 0);
        ret = krb5_mk_ncred(ctx, auth, (krb5_creds *[]){&creds, cr_creds, NULL}, cred_data, NULL);

        krb5_auth_con_free(ctx, auth);
out_auth:
        if (cr_creds != NULL) {
                explicit_bzero(cr_creds->ticket.data, cr_creds->ticket.length);
                explicit_bzero(cr_creds->keyblock.contents, cr_creds->keyblock.length);
                krb5_free_creds(ctx, cr_creds);
        }
out_cr_creds:
        explicit_bzero(creds.ticket.data, creds.ticket.length);
        explicit_bzero(creds.keyblock.contents, creds.keyblock.length);
        krb5_free_cred_contents(ctx, &creds);
out_creds:
        krb5_free_principal(ctx, serv);
out_serv:
        krb5_free_principal(ctx, clnt);
out_clnt:
        krb5_cc_close(ctx, ccache);
out_ccache:
        krb5_free_default_realm(ctx, realm);
out_realm:
        return (ret);
}
