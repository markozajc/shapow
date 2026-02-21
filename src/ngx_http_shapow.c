//SPDX-License-Identifier: AGPL-3.0-only
/*
 * SHAPOW - proof-of-work captcha module for nginx
 * Copyright (C) 2026 Marko Zajc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "config.h"
#include <ngx_http.h>
#include <endian.h>
#include <sys/random.h>
#include <openssl/sha.h>

#if __STDC_VERSION__ <= 201710
typedef enum {
	true = 1,
	false = 0
} bool;
#endif

/* ===================================================
 * preprocessor and struct definitions
 =================================================== */
#if !defined(NGX_HTTP_SHAPOW_ENABLE_IPV4) && !defined(NGX_HTTP_SHAPOW_ENABLE_IPV6)
#error One or both of NGX_HTTP_SHAPOW_ENABLE_IPV4 and NGX_HTTP_SHAPOW_ENABLE_IPV6 must be defined
#endif

#define NGX_HTTP_SHAPOW_STR_HELPER(x) #x
#define NGX_HTTP_SHAPOW_STR(x) NGX_HTTP_SHAPOW_STR_HELPER(x)

#define NGX_HTTP_SHAPOW_CHALL_SETTINGS_FORMAT \
	"const nonceLength = " NGX_HTTP_SHAPOW_STR(NGX_HTTP_SHAPOW_NONCE_LENGTH)";\n" \
	"const difficulty = %i;\n" \
	"const serverData = '%V%016xi%016xi';\n" /* serverData length must be a multiple of 4 bytes (8 characters in hex)
												due to constraints in Uint32Array */

// 256 bytes is arbitrarily decided, but it should be more than plenty for this format
#define NGX_HTTP_SHAPOW_CHALLENGE_SETTINGS_BUF_LEN 256

// challenge = hex(ip (ipv4 is padded to 16 bytes) || ngx_time() || random_challenge)
#define NGX_HTTP_SHAPOW_CHALLENGE_LENGTH (sizeof(struct in6_addr) + sizeof(int64_t) + sizeof(uint64_t))
#define NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH (NGX_HTTP_SHAPOW_CHALLENGE_LENGTH + NGX_HTTP_SHAPOW_NONCE_LENGTH)

#define ngx_http_shapow_destroy_bucket(TYPE, POOL, BUCKET) { \
	TYPE *node = (BUCKET);  /* NOSONAR can't enclose type in parens */ \
	while(node != NULL) { \
		TYPE *next_node = node->next;  /* NOSONAR can't enclose type in parens */ \
		ngx_slab_free_locked((POOL), node); \
		node = next_node; \
	} \
	(BUCKET) = NULL; \
}

#define ngx_http_shapow_prune_old_whitelists_for_bucket(TYPE, SHPOOL, BUCKET, PRUNE_BELOW) { \
	TYPE *node_prev = NULL; /* NOSONAR can't enclose type in parens */ \
	TYPE *node = (BUCKET); /* NOSONAR can't enclose type in parens */ \
	while (node != NULL) { \
		TYPE *node_next = node->next; /* NOSONAR can't enclose type in parens */ \
		if (node->data.ordinal <= (PRUNE_BELOW)) { \
			ngx_slab_free_locked((SHPOOL), node); \
			if (node_prev == NULL) \
				(BUCKET) = node_next; \
			else \
				node_prev->next = node_next; \
		} else { \
			node_prev = node; \
		} \
		node = node_next; \
	} \
}

#define ngx_http_shapow_upsert_address_for_family(DATA, TYPE, CONF, CTX, ADDR, BUCKET) { \
	TYPE *node = ngx_slab_alloc_locked((CTX)->shpool, sizeof(TYPE)); /* NOSONAR can't enclose type in parens */ \
	if (node == NULL) { \
		ngx_http_shapow_prune_old_whitelists((CONF), (CTX)); \
		node = ngx_slab_alloc_locked((CTX)->shpool, sizeof(TYPE)); /* NOSONAR can't enclose type in parens */ \
	} \
	if (node != NULL) { \
		node->addr = (ADDR); \
		node->next = (BUCKET); \
		(BUCKET) = node; \
		(DATA) = &node->data; \
	} \
}

typedef struct {
	uint32_t ordinal;
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	uint32_t use_count; // doesn't get incremented if whitelist_count in conf is 0
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	int32_t registration_time;
#endif
} ngx_http_shapow_node_t;

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
struct ngx_http_shapow_node4_s {
	struct ngx_http_shapow_node4_s *next;
	ngx_http_shapow_node_t data;
	struct in_addr addr;
};
typedef struct ngx_http_shapow_node4_s ngx_http_shapow_node4_t;
#endif

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
struct ngx_http_shapow_node6_s {
	struct ngx_http_shapow_node6_s *next;
	ngx_http_shapow_node_t data;
	struct in6_addr addr;
};
typedef struct ngx_http_shapow_node6_s ngx_http_shapow_node6_t;
#endif

typedef struct {
	uint32_t next_ordinal;
	uint32_t last_prune_ordinal;

// keep one table for each address family. the alternative (storing address family in the node) seems less efficient
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
	ngx_http_shapow_node4_t **table4;
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
	ngx_http_shapow_node6_t **table6;
#endif
} ngx_http_shapow_shctx_t;

typedef struct {
	ngx_slab_pool_t *shpool;
	ngx_http_shapow_shctx_t *sh;
	ngx_uint_t bucket_count;
	time_t epoch;

	// Part of the challenge is random to prevent generating solutions in advance. The random number is regenerated
	// every time the module is reloaded.
	uint64_t random_challenge;

	// Makes worst-case hash attacks even more difficult to pull off.
	ngx_uint_t hash_seed;
} ngx_http_shapow_ctx_t;

typedef struct {
	ngx_flag_t enabled;
	ngx_str_t zone_name;
	ngx_uint_t difficulty;
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	ngx_uint_t whitelist_count;
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	time_t whitelist_duration;
#endif
	ngx_str_t challenge_html_path;
	ngx_str_t challenge_css_path;
	ngx_str_t challenge_js_path;
	ngx_str_t challenge_worker_path;

	ngx_shm_zone_t *zone; // holds ngx_http_shapow_ctx_t

	u_char *challenge_html;
	ssize_t challenge_html_size;

	u_char *challenge_css;
	ssize_t challenge_css_size;

	u_char *challenge_js;
	ssize_t challenge_js_size;

	u_char *challenge_worker;
	ssize_t challenge_worker_size;
} ngx_http_shapow_loc_conf_t;

static ngx_int_t ngx_http_shapow_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_shapow(ngx_conf_t *cf);

static void* ngx_http_shapow_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_shapow_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_shapow_handler(ngx_http_request_t *r);

static char* ngx_http_shapow_zone_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_str_t ngx_http_shapow_pass = ngx_string("shapow_pass");
static ngx_uint_t ngx_http_shapow_pass_index;
static const ngx_str_t ngx_http_shapow_pass_data_yes = ngx_string("PASS");
static const ngx_str_t ngx_http_shapow_pass_data_no = ngx_string("LIMIT");

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

//@formatter:off
static ngx_command_t ngx_http_shapow_commands[] = {
	{
		ngx_string("shapow_zone_add"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
		ngx_http_shapow_zone_add,
		0,
		0,
		NULL
	},
	{
		ngx_string("shapow"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, enabled),
		NULL
	},
	{
		ngx_string("shapow_zone"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, zone_name),
		NULL
	},
	{
		ngx_string("shapow_difficulty"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, difficulty),
		NULL
	},
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	{
		ngx_string("shapow_whitelist_count"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, whitelist_count),
		NULL
	},
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	{
		ngx_string("shapow_whitelist_duration"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_sec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, whitelist_duration),
		NULL
	},
#endif
	{
		ngx_string("shapow_challenge_html_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, challenge_html_path),
		NULL
	},
	{
		ngx_string("shapow_challenge_css_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, challenge_css_path),
		NULL
	},
	{
		ngx_string("shapow_challenge_js_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, challenge_js_path),
		NULL
	},
	{
		ngx_string("shapow_challenge_worker_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_shapow_loc_conf_t, challenge_worker_path),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_shapow_module_ctx = {
	ngx_http_shapow_add_variables,
	ngx_http_shapow,

	NULL,
	NULL,

	NULL,
	NULL,

	ngx_http_shapow_create_loc_conf,
	ngx_http_shapow_merge_loc_conf
};

ngx_module_t ngx_http_shapow_module = {
	NGX_MODULE_V1,
	&ngx_http_shapow_module_ctx,
	ngx_http_shapow_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};
//@formatter:on

/* ===================================================
 * utilities
 =================================================== */
static ngx_int_t ngx_http_shapow_read_file_into(ngx_conf_t *cf, ngx_str_t *name, u_char **dest, ssize_t *size) {
	ngx_file_t file = {0};
	file.name = *name;
	file.log = cf->log;

	file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
	if (file.fd == NGX_INVALID_FILE) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_open_file_n " \"%V\" failed", name);
		return NGX_ERROR;
	}

	if (ngx_fd_info(file.fd, &file.info) == NGX_FILE_ERROR) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno, ngx_fd_info_n " \"%V\" failed", name);
		return NGX_ERROR;
	}

	*size = ngx_file_size(&file.info);
	if (*size > 1992294 /* 1.9 MiB */) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "Resource file \"%V\" is too large, the limit is 1.9 MiB", name);
		return NGX_ERROR;
	}

	*dest = ngx_palloc(cf->pool, *size);
	if (*dest == NULL) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "Out of memory when reading file \"%V\"", name);
		return NGX_ERROR;
	}

	ssize_t read = ngx_read_file(&file, *dest, *size, 0);
	if (read == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno, ngx_read_file_n " \"%V\" failed", name);
		return NGX_ERROR;

	} else if (read != *size) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, ngx_read_file_n " \"%V\" returned only %z bytes instead of %z", name,
				read, *size);
		return NGX_ERROR;
	}

	if (ngx_close_file(file.fd) == NGX_FILE_ERROR)
		ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", name);

	return NGX_OK;
}

static ngx_int_t ngx_http_shapow_str_eq(const ngx_str_t *s1, const ngx_str_t *s2) {
	if (s1->len != s2->len)
		return 0;
	return ngx_strncmp(s1->data, s2->data, s1->len) == 0;
}

static ngx_int_t ngx_http_shapow_str_ends_with(const ngx_str_t *str, const char *suffix, size_t suffix_len) {
	if (str->len < suffix_len)
		return 0;
	return ngx_strncmp(str->data + (str->len - suffix_len), suffix, suffix_len) == 0;
}

static void ngx_http_shapow_fill_hex(const u_char *data, u_char *out, size_t size) {
	for (size_t i = 0; i < size * 2; ++i) {
		u_char c = data[i / 2];
		if (i % 2 == 0)
			c = c >> 4;
		c &= 0x0f;
		c = (u_char) (c + ((c <= 9) ? '0' : ('a' - 10)));
		out[i] = c;
	}
}

/* ===================================================
 * module setup functions
 =================================================== */
static void* ngx_http_shapow_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_shapow_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_shapow_loc_conf_t));
	if (!conf)
		return NULL;

	/* NOSONAR
	 * set by pcalloc:
	 *     conf->zone_name = { 0, NULL };
	 *     conf->challenge_html_path = { 0, NULL };
	 *     conf->challenge_css_path = { 0, NULL };
	 *     conf->challenge_js_path = { 0, NULL };
	 *     conf->challenge_worker_path = { 0, NULL };
	 *     conf->zone = NULL;
	 *     conf->challenge_html = NULL;
	 *     conf->challenge_css = NULL;
	 *     conf->challenge_js = NULL;
	 *     conf->challenge_worker = NULL;
	 */

	conf->enabled = NGX_CONF_UNSET;
	conf->difficulty = NGX_CONF_UNSET_UINT;
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	conf->whitelist_count = NGX_CONF_UNSET_UINT;
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	conf->whitelist_duration = NGX_CONF_UNSET;
#endif

	return conf;
}

static char* ngx_http_shapow_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) { // NOSONAR function is readable
	ngx_http_shapow_loc_conf_t *prev = parent;
	ngx_http_shapow_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enabled, prev->enabled, 0)
	ngx_conf_merge_str_value(conf->zone_name, prev->zone_name, "")
	ngx_conf_merge_uint_value(conf->difficulty, prev->difficulty, 12)
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	ngx_conf_merge_uint_value(conf->whitelist_count, prev->whitelist_count, 0)
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	ngx_conf_merge_sec_value(conf->whitelist_duration, prev->whitelist_duration, 0)
#endif
	ngx_conf_merge_str_value(conf->challenge_html_path, prev->challenge_html_path,
			NGX_HTTP_SHAPOW_RESOURCE_ROOT "/challenge.html")
	ngx_conf_merge_str_value(conf->challenge_css_path, prev->challenge_css_path,
			NGX_HTTP_SHAPOW_RESOURCE_ROOT "/challenge.css")
	ngx_conf_merge_str_value(conf->challenge_js_path, prev->challenge_js_path,
			NGX_HTTP_SHAPOW_RESOURCE_ROOT "/challenge.js")
	ngx_conf_merge_str_value(conf->challenge_worker_path, prev->challenge_worker_path,
			NGX_HTTP_SHAPOW_RESOURCE_ROOT "/challenge-worker.js")

	if (!conf->enabled)
		return NGX_OK;

	if (conf->zone_name.len == 0) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "shapow_zone directive is required when SHAPOW is enabled");
		return NGX_CONF_ERROR ;
	}

	if (conf->difficulty > SHA256_DIGEST_LENGTH * 8) {
		ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "shapow_difficulty must be between 0 and %ui",
				(ngx_uint_t) SHA256_DIGEST_LENGTH * 8);
		return NGX_CONF_ERROR ;
	}

	// use file data from prev if they use the same paths and prev is enabled, otherwise read the file (for all 4 files)

	// challenge_html
	if (prev->enabled && prev->challenge_html_path.len > 0
			&& ngx_http_shapow_str_eq(&prev->challenge_html_path, &conf->challenge_html_path)) {
		conf->challenge_html = prev->challenge_html;

	} else if (ngx_http_shapow_read_file_into(cf, &conf->challenge_html_path, &conf->challenge_html,
			&conf->challenge_html_size) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	// challenge_css
	if (conf->challenge_css_path.len == 0) {
		conf->challenge_css = NULL;

	} else if (prev->enabled && prev->challenge_css_path.len > 0
			&& ngx_http_shapow_str_eq(&prev->challenge_css_path, &conf->challenge_css_path)) {
		conf->challenge_css = prev->challenge_css;

	} else if (ngx_http_shapow_read_file_into(cf, &conf->challenge_css_path, &conf->challenge_css,
			&conf->challenge_css_size) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	// challenge_js
	if (conf->challenge_js_path.len == 0) {
		conf->challenge_js = NULL;

	} else if (prev->enabled && prev->challenge_js_path.len > 0
			&& ngx_http_shapow_str_eq(&prev->challenge_js_path, &conf->challenge_js_path)) {
		conf->challenge_js = prev->challenge_js;

	} else if (ngx_http_shapow_read_file_into(cf, &conf->challenge_js_path, &conf->challenge_js,
			&conf->challenge_js_size) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	// challenge_worker
	if (conf->challenge_worker_path.len == 0) {
		conf->challenge_worker = NULL;

	} else if (prev->enabled && prev->challenge_worker_path.len > 0
			&& ngx_http_shapow_str_eq(&prev->challenge_worker_path, &conf->challenge_worker_path)) {
		conf->challenge_worker = prev->challenge_worker;

	} else if (ngx_http_shapow_read_file_into(cf, &conf->challenge_worker_path, &conf->challenge_worker,
			&conf->challenge_worker_size) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	// map shared memory
	if (prev->enabled && prev->zone_name.len > 0 && ngx_http_shapow_str_eq(&prev->zone_name, &conf->zone_name)) {
		conf->zone = prev->zone;

	} else {
		conf->zone = ngx_shared_memory_add(cf, &conf->zone_name, 0, &ngx_http_shapow_module);
		if (conf->zone == NULL)
			return NGX_CONF_ERROR ;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http_shapow_init_zone_tables(ngx_http_shapow_ctx_t *ctx) {
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
	ctx->sh->table4 = ngx_slab_calloc_locked(ctx->shpool, ctx->bucket_count * sizeof(ngx_http_shapow_node4_t*));
	if (ctx->sh->table4 == NULL)
		return NGX_ERROR;
#endif

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
	ctx->sh->table6 = ngx_slab_calloc_locked(ctx->shpool, ctx->bucket_count * sizeof(ngx_http_shapow_node6_t*));
	if (ctx->sh->table6 == NULL)
		return NGX_ERROR;
#endif

	// set a random hash seed
	if (getrandom((char*) &ctx->hash_seed, sizeof(ctx->hash_seed), 0) != sizeof(ctx->hash_seed)) {
		ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "SHAPOW: failed to generate random bytes");
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http_shapow_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_http_shapow_ctx_t *ctx = shm_zone->data;

	// try reusing old data from reload
	ngx_http_shapow_ctx_t *octx = data;
	if (octx) {
		ctx->random_challenge = octx->random_challenge;
		ctx->epoch = octx->epoch;
		ctx->sh = octx->sh;
		ctx->shpool = octx->shpool;

		if (octx->bucket_count == ctx->bucket_count) {
			ctx->hash_seed = octx->hash_seed;
			return NGX_OK;

		} else {
			ctx->sh->next_ordinal = 0;
			ctx->sh->last_prune_ordinal = 0;

			ngx_shmtx_lock(&ctx->shpool->mutex);

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
			for (size_t bucket = 0; bucket < octx->bucket_count; ++bucket)
				ngx_http_shapow_destroy_bucket(ngx_http_shapow_node4_t, ctx->shpool, ctx->sh->table4[bucket]);
			ngx_slab_free_locked(ctx->shpool, ctx->sh->table4);
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
			for (size_t bucket = 0; bucket < octx->bucket_count; ++bucket)
				ngx_http_shapow_destroy_bucket(ngx_http_shapow_node6_t, ctx->shpool, ctx->sh->table6[bucket]);
			ngx_slab_free_locked(ctx->shpool, ctx->sh->table6);
#endif

			ngx_int_t rc = ngx_http_shapow_init_zone_tables(ctx);

			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return rc;
		}
	}

	ctx->shpool = (ngx_slab_pool_t*) shm_zone->shm.addr;

	if (shm_zone->shm.exists) { // Windows-specific
		ctx->sh = ctx->shpool->data;
		return NGX_OK;
	}

	// initialize the shared zone
	ngx_shmtx_lock(&ctx->shpool->mutex);

	ctx->sh = ngx_slab_alloc_locked(ctx->shpool, sizeof(ngx_http_shapow_shctx_t));
	/* set by calloc:
	 *     conf->last_prune_ordinal = 0
	 *     conf->next_ordinal = 0
	 */
	if (ctx->sh == NULL) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);
		return NGX_ERROR;
	}
	ctx->shpool->data = ctx->sh;

	// initialize misc variables
	ctx->epoch = ngx_time();

	if (getrandom((char*) &ctx->random_challenge, sizeof(ctx->random_challenge), 0) != sizeof(ctx->random_challenge)) {
		ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "SHAPOW: failed to generate random bytes");
		ngx_shmtx_unlock(&ctx->shpool->mutex);
		return NGX_ERROR;
	}

	// initialize zone tables
	ngx_int_t rc = ngx_http_shapow_init_zone_tables(ctx);

	if (rc != NGX_OK) {
		ngx_shmtx_unlock(&ctx->shpool->mutex);
		return rc;
	}

	// initialize logging
	size_t len = sizeof(" in SHAPOW zone \"\"") + shm_zone->shm.name.len;

	ctx->shpool->log_ctx = ngx_slab_alloc_locked(ctx->shpool, len);
	ngx_shmtx_unlock(&ctx->shpool->mutex);
	if (ctx->shpool->log_ctx == NULL)
		return NGX_ERROR;

	ngx_sprintf(ctx->shpool->log_ctx, " in SHAPOW zone \"%V\"%Z", &shm_zone->shm.name);

	ctx->shpool->log_nomem = 0;

	return NGX_OK;
}

static char* ngx_http_shapow_zone_add(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
	(void) (data); // unused

	ngx_http_shapow_ctx_t *ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_shapow_ctx_t));
	if (ctx == NULL)
		return NGX_CONF_ERROR ;

	ngx_str_t *value = cf->args->elts;

	ssize_t size = ngx_parse_size(&value[2]);
	if (size == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size \"%V\"", &value[2]);
		return NGX_CONF_ERROR ;
	}

	ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &value[1], size, &ngx_http_shapow_module);
	if (shm_zone == NULL)
		return NGX_CONF_ERROR ;

	if (shm_zone->data) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V \"%V\" is already used", &cmd->name, &value[1]);
		return NGX_CONF_ERROR ;
	}

	ctx->bucket_count = ngx_atoi(value[3].data, value[3].len);
	if (ctx->bucket_count <= 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid bucket count \"%V\"", &value[3]);
		return NGX_CONF_ERROR ;
	}

	shm_zone->init = ngx_http_shapow_init_zone;
	shm_zone->data = ctx;

	return NGX_CONF_OK;
}

/* ===================================================
 * request handler
 =================================================== */
static ngx_int_t ngx_http_shapow_serve_buffer(ngx_http_request_t *r, u_char *buf, ssize_t size) {
	ngx_buf_t *ngx_buf = ngx_calloc_buf(r->pool);
	if (ngx_buf == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "SHAPOW: out of memory when allocating a ngx_buf_t");
		return NGX_ERROR;
	}

	ngx_buf->pos = buf;
	ngx_buf->last = buf + size;
	ngx_buf->memory = 1;
	ngx_buf->last_buf = 1;

	ngx_chain_t *chain_link = ngx_alloc_chain_link(r->pool);
	if (chain_link == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "SHAPOW: out of memory when allocating a ngx_chain_t");
		return NGX_ERROR;
	}

	chain_link->buf = ngx_buf;
	chain_link->next = NULL;

	r->headers_out.content_length_n = size;

	if (ngx_http_send_header(r) == NGX_ERROR)
		return NGX_ERROR;

	ngx_http_finalize_request(r, ngx_http_output_filter(r, chain_link));
	return NGX_DONE;
}

static ngx_int_t ngx_http_shapow_serve_challenge_settings(ngx_http_request_t *r, const ngx_http_shapow_ctx_t *ctx,
														  const ngx_http_shapow_loc_conf_t *conf) {
	const struct sockaddr *sa = r->connection->sockaddr;
	u_char addr[sizeof(struct in6_addr) * 2 /* hex */]; // NOSONAR initialized right after
	ngx_str_t addr_str = {sizeof(addr), addr};
	// using %ix formats will reorder bytes and make everything unnecessarily difficult, so we use our own hex encoder
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa_in = (const struct sockaddr_in*) sa;
		ngx_http_shapow_fill_hex((const u_char*) &sa_in->sin_addr.s_addr, addr, sizeof(in_addr_t));
		ngx_memset(addr + sizeof(in_addr_t) * 2, '0', sizeof(addr) - sizeof(in_addr_t) * 2); // fill rest with '0'

	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6*) sa;
		ngx_http_shapow_fill_hex((const u_char*) &sa_in6->sin6_addr.s6_addr, addr, sizeof(struct in6_addr));

	} else {
		ngx_memset(addr, '0', sizeof(addr));
	}

	u_char *buf = ngx_palloc(r->pool, NGX_HTTP_SHAPOW_CHALLENGE_SETTINGS_BUF_LEN);
	if (buf == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
				"SHAPOW: out of memory when allocating a challenge settings buffer");
		return NGX_ERROR;
	}

	const u_char *end = ngx_snprintf(buf, NGX_HTTP_SHAPOW_CHALLENGE_SETTINGS_BUF_LEN,
			(NGX_HTTP_SHAPOW_CHALL_SETTINGS_FORMAT), conf->difficulty, &addr_str, (ngx_int_t) ngx_time(), // NOSONAR cast isn't redundant
			(ngx_uint_t) ctx->random_challenge); // NOSONAR ditto

	if (end >= buf + NGX_HTTP_SHAPOW_CHALLENGE_SETTINGS_BUF_LEN) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "SHAPOW: challenge settings buffer is too small");
		return NGX_ERROR;
	}

	return ngx_http_shapow_serve_buffer(r, buf, end - buf);
}

static u_char* ngx_http_shapow_find_challenge_response(const ngx_str_t *args) {
	// starts with "shapow-response=..."
	if (args->len < (sizeof(NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG) + NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2))
		return NULL;

	u_char *start; // NOSONAR initialized right after
	if (ngx_strncmp(args->data, NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG "=",
			sizeof(NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG)) == 0) {
		start = args->data;

	} else {
		start = ngx_strnstr(args->data, (char*) "&" NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG "=", args->len); // NOSONAR removal of const is safe here
		if (start == NULL)
			return NULL;
		++start; // skip "&"
	}

	start += sizeof(NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG); // skip "shapow-response="
	size_t len = args->len - (start - args->data); // length between start (our pointer) and end of args

	bool valid = (len == NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2)
			|| (len > NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2
					&& start[NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2] == '&');
	// check that the length either matches exactly, or is greater but extra arguments are separated with a '&'

	return valid ? start : NULL;
}

static bool ngx_http_shapow_check_response_difficulty(const u_char *challenge_response, ngx_uint_t difficulty) {
	u_char hash[SHA256_DIGEST_LENGTH]; // NOSONAR initialized right after
	SHA256(challenge_response, NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH, hash);

	size_t i = 0;
	while (difficulty > 8) {
		if (hash[i++] != 0)
			return false;
		difficulty -= 8;
	}

	return (0xFF << (8 - difficulty) & 0xFF & hash[i]) == 0;
}

static bool ngx_http_shapow_check_challenge_response(const ngx_http_request_t *r, const ngx_http_shapow_ctx_t *ctx,
													 const ngx_http_shapow_loc_conf_t *conf, const u_char *response) {
	// parse hex response to binary
	u_char data[NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH] = {0};
	for (size_t i = 0; i < NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2; ++i) {
		u_char c = response[i];
		if ('0' <= c && '9' >= c)
			c -= '0';
		else if ('a' <= c && 'f' >= c)
			c -= 'a' - 10;
		else if ('A' <= c && 'F' >= c)
			c -= 'A' - 10;
		else
			return false;

		if (i % 2 == 0)
			c = c << 4; // NOSONAR loss of precision is not a problem

		data[i / 2] |= c;
	}

	// check response IP
	const struct sockaddr *sa = r->connection->sockaddr;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa_in = (const struct sockaddr_in*) sa;
		static const uint32_t zeroes[3] = {0};
		if (ngx_memcmp(data, &sa_in->sin_addr.s_addr, sizeof(sa_in->sin_addr)) != 0)
			return false;

		if (ngx_memcmp(data+4, zeroes, sizeof(zeroes)) != 0)
			return false;

	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6*) sa;
		if (ngx_memcmp(data, &sa_in6->sin6_addr.s6_addr, sizeof(sa_in6->sin6_addr.s6_addr)) != 0)
			return false;

	} else
		return true; // not checking at all for non-INET addresses

	// check response time
	// I'm not sure how/when nginx's time cache is updated, but it's probably not safe to assume it's the same for all
	// workers, so I'm allowing the possibility that resp_time is higher than ngx_time()
	int64_t resp_time; // NOSONAR initialized right after
	memcpy(&resp_time, data + sizeof(struct in6_addr), sizeof(resp_time));
	resp_time = be64toh(resp_time);
	if (ngx_abs(ngx_time() - resp_time) > NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_MAX_TIME_DIFFERENCE)
		return false;

	// check random challenge
	uint64_t resp_random_challenge; // NOSONAR initialized right after
	memcpy(&resp_random_challenge, data + sizeof(struct in6_addr) + sizeof(int64_t), sizeof(resp_random_challenge));
	resp_random_challenge = be64toh(resp_random_challenge);
	if (resp_random_challenge != ctx->random_challenge)
		return false;

	// check difficulty
	if (!ngx_http_shapow_check_response_difficulty(data, conf->difficulty))
		return false;

	return 1;
}

static ngx_uint_t ngx_http_shapow_get_address_bucket_id(const ngx_http_shapow_ctx_t *ctx, const struct sockaddr *sa) {
	uint32_t hash; // NOSONAR initialized right after
	ngx_crc32_init(hash);
	ngx_crc32_update(&hash, (u_char*) &ctx->hash_seed, sizeof(ctx->hash_seed)); // NOSONAR can't pass const

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa_in = (const struct sockaddr_in*) sa;
		ngx_crc32_update(&hash, (u_char*) &sa_in->sin_addr.s_addr, sizeof(sa_in->sin_addr.s_addr)); // NOSONAR can't pass const

	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6*) sa;
		ngx_crc32_update(&hash, (u_char*) &sa_in6->sin6_addr.s6_addr, sizeof(sa_in6->sin6_addr.s6_addr)); // NOSONAR can't pass const
	}
	// for non-INET sockaddrs are already ignored by the handler

	ngx_crc32_final(hash);
	return hash % ctx->bucket_count;
}

static ngx_http_shapow_node_t* ngx_http_shapow_lookup_address(const ngx_http_shapow_ctx_t *ctx, ngx_uint_t bucket_id,
															  const struct sockaddr *sa) {
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa_in = (const struct sockaddr_in*) sa;

		ngx_http_shapow_node4_t *node = ctx->sh->table4[bucket_id];
		while (node != NULL && ngx_memcmp(&node->addr, &sa_in->sin_addr, sizeof(node->addr)) != 0)
			node = node->next;

		if (node == NULL)
			return NULL;

		return &node->data; // @suppress("Returning the address of a local variable")
	}
#endif

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6*) sa;

		ngx_http_shapow_node6_t *node = ctx->sh->table6[bucket_id];
		while (node != NULL && ngx_memcmp(&node->addr, &sa_in6->sin6_addr, sizeof(node->addr)) != 0)
			node = node->next;

		if (node == NULL)
			return NULL;

		return &node->data; // @suppress("Returning the address of a local variable")
	}
#endif

	return NULL;
}

static void ngx_http_shapow_prune_old_whitelists(const ngx_http_shapow_loc_conf_t *conf, ngx_http_shapow_ctx_t *ctx) {
	uint32_t prune_below; // NOSONAR initialized right after
	// overflows happen every 4 billion whitelist inserts (assuming we don't restart nginx in that time!), so more
	// advanced handling logic isn't really necessary
	if (ctx->sh->last_prune_ordinal <= ctx->sh->next_ordinal) {
		// next_ordinal did not overflow
		prune_below = ctx->sh->last_prune_ordinal + (ctx->sh->next_ordinal - ctx->sh->last_prune_ordinal) / 2;
		ctx->sh->last_prune_ordinal = prune_below;

	} else {
		// next_ordinal did overflow
		prune_below = -1; // prune all buckets
		ctx->sh->last_prune_ordinal = 0;
	}

	ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "SHAPOW zone %V: current node ordinal is %ui, pruning nodes <= %ui",
			&conf->zone_name, (ngx_uint_t ) ctx->sh->next_ordinal, (ngx_uint_t ) prune_below);

	for (size_t bucket_id = 0; bucket_id < ctx->bucket_count; ++bucket_id) {
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
		ngx_http_shapow_prune_old_whitelists_for_bucket(ngx_http_shapow_node4_t, ctx->shpool,
				ctx->sh->table4[bucket_id], prune_below)
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
		ngx_http_shapow_prune_old_whitelists_for_bucket(ngx_http_shapow_node6_t, ctx->shpool,
				ctx->sh->table6[bucket_id], prune_below)
#endif
	}
}

static ngx_int_t ngx_http_shapow_upsert_address(const ngx_http_request_t *r, const ngx_http_shapow_loc_conf_t *conf,
												ngx_http_shapow_ctx_t *ctx, const struct sockaddr *sa) {
	ngx_uint_t bucket_id = ngx_http_shapow_get_address_bucket_id(ctx, sa);

	ngx_shmtx_lock(&ctx->shpool->mutex);
	ngx_http_shapow_node_t *data = ngx_http_shapow_lookup_address(ctx, bucket_id, sa);

	if (data == NULL) {
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
		if (sa->sa_family == AF_INET) {
			const struct sockaddr_in *sa_in = (const struct sockaddr_in*) sa;
			ngx_http_shapow_upsert_address_for_family(data, ngx_http_shapow_node4_t, conf, ctx, sa_in->sin_addr,
					ctx->sh->table4[bucket_id]);
		}
#endif

#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
		if (sa->sa_family == AF_INET6) {
			const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6*) sa;
			ngx_http_shapow_upsert_address_for_family(data, ngx_http_shapow_node6_t, conf, ctx, sa_in6->sin6_addr,
					ctx->sh->table6[bucket_id]);
		}
#endif

		if (data != NULL) {
			data->ordinal = ctx->sh->next_ordinal++;

		} else {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "SHAPOW zone \"%V\" is not big enough",
					&conf->zone_name);
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_ERROR;
		}
	}

#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
	data->use_count = 0;
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
	data->registration_time = (int32_t) (ngx_time() - ctx->epoch); // cast is safe, 2^31 seconds = 68 years
#endif

	ngx_shmtx_unlock(&ctx->shpool->mutex);
	return NGX_OK;
}

static bool ngx_http_shapow_addr_family_supported(sa_family_t sa_family) {
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV4
	if (sa_family == AF_INET)
		return true;
#endif
#ifdef NGX_HTTP_SHAPOW_ENABLE_IPV6
	if (sa_family == AF_INET6)
		return true;
#endif
	return false;
}

static ngx_int_t ngx_http_shapow_should_serve_challenge(ngx_http_request_t *r, const ngx_http_shapow_loc_conf_t *conf,
														ngx_http_shapow_ctx_t *ctx) {
	const struct sockaddr *sa = r->connection->sockaddr;

	// allow non-INET addresses
	if (!ngx_http_shapow_addr_family_supported(sa->sa_family))
		return NGX_DECLINED;

	// check if response has a valid challenge response
	u_char *challenge_response = ngx_http_shapow_find_challenge_response(&r->args);
	if (challenge_response) {
		if (!ngx_http_shapow_check_challenge_response(r, ctx, conf, challenge_response))
			return NGX_OK;

		if (ngx_http_shapow_upsert_address(r, conf, ctx, sa) == NGX_ERROR)
			return NGX_ERROR;

		// remove challenge_response from the URL so it's not read by other modules/directives
		u_char *resp_arg_start = challenge_response - sizeof(NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG);
		size_t resp_arg_len = sizeof(NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG)
				+ NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_LENGTH * 2;

		size_t leading_len = resp_arg_start - r->args.data;
		size_t trailing_len = r->args.len - leading_len - resp_arg_len;
		if (leading_len == 0 && trailing_len == 0) {
			r->args.len = 0;

		} else if (leading_len != 0 && trailing_len == 0) {
			r->args.len = leading_len - 1 /* '&' */;

		} else if (leading_len == 0 && trailing_len != 0) {
			r->args.len = trailing_len - 1 /* '&' */;
			r->args.data += resp_arg_len + 1 /* '&' */;

		} else {
			ngx_memmove(resp_arg_start, resp_arg_start + resp_arg_len + 1, trailing_len - 1);
			r->args.len = leading_len + trailing_len - 1;
		}

		return NGX_DECLINED;

	} else {
		ngx_shmtx_lock(&ctx->shpool->mutex);
		// locking a little wasteful, but it prevents a data race when freeing stale nodes
		ngx_http_shapow_node_t *data = ngx_http_shapow_lookup_address(ctx,
				ngx_http_shapow_get_address_bucket_id(ctx, sa), sa);

		// node is not whitelisted
		if (data == NULL) {
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_OK;
		}

#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
		// whitelist has expired (has more uses than whitelist_count)
		ngx_uint_t count = conf->whitelist_count;
		if (count && (data->use_count++ > count)) { // NOSONAR short-circuited increment is intentional
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_OK;
		}
#endif

#ifdef NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION
		// whitelist has expired (is older than whitelist_duration)
		time_t duration = conf->whitelist_duration;
		if (duration && (ngx_time() - ctx->epoch - data->registration_time) > duration) {
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_OK;
		}
#endif

		ngx_shmtx_unlock(&ctx->shpool->mutex);
		return NGX_DECLINED;
	}
}

static ngx_int_t ngx_http_shapow_handler(ngx_http_request_t *r) { // NOSONAR
	const ngx_http_shapow_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_shapow_module);
	if (!conf->enabled)
		return NGX_DECLINED;

	// internal redirects will run our handler multiple times, clearing module ctx between runs. variables are a good
	// way to persist data between these requests
	ngx_variable_value_t *pass_var = &r->variables[ngx_http_shapow_pass_index];
	if (pass_var->data == ngx_http_shapow_pass_data_yes.data) {
		return NGX_DECLINED;

	} else {
		pass_var->valid = 1;
		pass_var->not_found = 0;
		pass_var->no_cacheable = 1;
		pass_var->data = ngx_http_shapow_pass_data_no.data;
		pass_var->len = ngx_http_shapow_pass_data_no.len;
	}

	ngx_http_shapow_ctx_t *ctx = conf->zone->data;

	static const ngx_str_t content_type_html = ngx_string("text/html;charset=utf-8");
	static const ngx_str_t content_type_js = ngx_string("text/javascript");
	static const ngx_str_t content_type_css = ngx_string("text/css");

	// always serve challenge resource files on their path suffixes
	if (conf->challenge_css
			&& ngx_http_shapow_str_ends_with(&r->uri, NGX_HTTP_SHAPOW_URI_CHALL_CSS,
					sizeof(NGX_HTTP_SHAPOW_URI_CHALL_CSS) - 1)) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type = content_type_css;
		return ngx_http_shapow_serve_buffer(r, conf->challenge_css, conf->challenge_css_size);

	} else if (conf->challenge_js
			&& ngx_http_shapow_str_ends_with(&r->uri, NGX_HTTP_SHAPOW_URI_CHALL_JS,
					sizeof(NGX_HTTP_SHAPOW_URI_CHALL_JS) - 1)) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type = content_type_js;
		return ngx_http_shapow_serve_buffer(r, conf->challenge_js, conf->challenge_js_size);

	} else if (conf->challenge_worker
			&& ngx_http_shapow_str_ends_with(&r->uri, NGX_HTTP_SHAPOW_URI_CHALL_WORKER,
					sizeof(NGX_HTTP_SHAPOW_URI_CHALL_WORKER) - 1)) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type = content_type_js;
		return ngx_http_shapow_serve_buffer(r, conf->challenge_worker, conf->challenge_worker_size);

	} else if (ngx_http_shapow_str_ends_with(&r->uri, NGX_HTTP_SHAPOW_URI_CHALL_SETTINGS,
			sizeof(NGX_HTTP_SHAPOW_URI_CHALL_SETTINGS) - 1)) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type = content_type_js;
		return ngx_http_shapow_serve_challenge_settings(r, ctx, conf);
	}

	// serve the challenge if necessary
	ngx_int_t rc = ngx_http_shapow_should_serve_challenge(r, conf, ctx);
	if (rc == NGX_OK) {
		r->headers_out.status = NGX_HTTP_TOO_MANY_REQUESTS;
		r->headers_out.content_type = content_type_html;
		return ngx_http_shapow_serve_buffer(r, conf->challenge_html, conf->challenge_html_size);

	} else if (rc == NGX_DECLINED) {
		pass_var->data = ngx_http_shapow_pass_data_yes.data;
		pass_var->len = ngx_http_shapow_pass_data_yes.len;
		return NGX_DECLINED;

	} else {
		return rc;
	}
}

static ngx_int_t ngx_http_shapow_pass_set_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) { // NOSONAR can't declare const
	(void) (r); // unused
	(void) (v); // unused
	(void) (data); // unused
	return NGX_OK;
}

static ngx_int_t ngx_http_shapow_add_variables(ngx_conf_t *cf) {
	ngx_http_variable_t *var = ngx_http_add_variable(cf, &ngx_http_shapow_pass, NGX_HTTP_VAR_NOCACHEABLE);
	var->get_handler = ngx_http_shapow_pass_set_var;
	if (var == NULL)
		return NGX_ERROR;

	ngx_int_t index = ngx_http_get_variable_index(cf, &ngx_http_shapow_pass);
	if (index == NGX_ERROR)
		return NGX_ERROR;

	ngx_http_shapow_pass_index = index;

	return NGX_OK;
}

static ngx_int_t ngx_http_shapow_header_filter(ngx_http_request_t *r) {
	const ngx_variable_value_t *pass_var = &r->variables[ngx_http_shapow_pass_index];
	if (pass_var == NULL || pass_var->data != ngx_http_shapow_pass_data_no.data)
		return ngx_http_next_header_filter(r);

	static const ngx_str_t header_csp_key = ngx_string("Content-Security-Policy");
	static const ngx_str_t header_csp_value = ngx_string(
			"default-src 'self';"
			"script-src 'self' 'unsafe-inline' 'unsafe-hashes' 'sha256-5sBVMf3rpfzmovinEBS+zknIk18/JTKQhrIdGhsXVoA='");
	// the hash corresponds to the inline <script> in challenge.html's <head>

	ngx_list_part_t *part = &r->headers_out.headers.part;
	ngx_table_elt_t *header = part->elts;

	for (ngx_uint_t i = 0;; ++i) {
		if (i >= part->nelts) {
			if (part->next == NULL)
				break;

			part = part->next;
			header = part->elts;

			i = 0;
		}

		ngx_str_t *key = &header[i].key;
		if (key->len == header_csp_key.len && ngx_strncasecmp(key->data, header_csp_key.data, key->len) == 0)
			header[i].hash = 0;
	}

	header = ngx_list_push(&r->headers_out.headers);
	if (header == NULL)
		return NGX_ERROR;
	header->hash = 1;
	header->key = header_csp_key;
	header->value = header_csp_value;

	return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_shapow(ngx_conf_t *cf) {
	ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_shapow_header_filter;

	ngx_http_handler_pt *h = ngx_array_push(&main_conf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL)
		return NGX_ERROR;

	*h = ngx_http_shapow_handler;

	return NGX_OK;
}
