//SPDX-License-Identifier: AGPL-3.0-only
/*
 * libnginx-mod-http-shapow - proof-of-work captcha module for nginx
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

// Default root for resource files that are read into memory on module startup.
#define NGX_HTTP_SHAPOW_RESOURCE_ROOT "/usr/share/libnginx-mod-http-shapow"

// Paths to serve resources on.
#define NGX_HTTP_SHAPOW_URI_ROOT "/shapow_internal"
#define NGX_HTTP_SHAPOW_URI_CHALL_CSS NGX_HTTP_SHAPOW_URI_ROOT "/challenge.css"
#define NGX_HTTP_SHAPOW_URI_CHALL_JS NGX_HTTP_SHAPOW_URI_ROOT "/challenge.js"
#define NGX_HTTP_SHAPOW_URI_CHALL_WORKER NGX_HTTP_SHAPOW_URI_ROOT "/challenge-worker.js"
#define NGX_HTTP_SHAPOW_URI_CHALL_SETTINGS NGX_HTTP_SHAPOW_URI_ROOT "/challenge-settings.js"

// Length (in bytes) of the nonce (= the challenge solution). Going too low can result in unsolvable challenges, which
// the client-side code is not programmed to support or detect.
#define NGX_HTTP_SHAPOW_NONCE_LENGTH 16

// Querystring argument used to return the challenge response. Make sure this doesn't conflict with your CGI/backend's
// querystring parameters. Must be changed separately in challenge.js.
#define NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_ARG "shapow-response"

// The validity duration of challenge responses. This is separate from whitelist duration, and should only accommodate
// the time to solve and return the response.
#define NGX_HTTP_SHAPOW_CHALLENGE_RESPONSE_MAX_TIME_DIFFERENCE 600 // 10 minutes

// These two defines control the availability of the shapow_whitelist_count and shapow_whitelist_duration directives.
// They incur some overhead on the whitelist data (4 bytes each), so disable them here if you don't use these
// directives.
#define NGX_HTTP_SHAPOW_ENABLE_WHITELIST_COUNT
#define NGX_HTTP_SHAPOW_ENABLE_WHITELIST_DURATION

// Similarly, you can disable support for protocols you don't need. This reclaims some memory, depending on your
// configured bucket count. Requests from disabled protocols will never be served a challenge, but can still access
// internal resources (/shapow_internal/*)
#define NGX_HTTP_SHAPOW_ENABLE_IPV4
#define NGX_HTTP_SHAPOW_ENABLE_IPV6
