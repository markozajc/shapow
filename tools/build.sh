#!/bin/bash
set -euo pipefail
if [ -z ${NGINX_PATH+x} ]; then
	echo "Please set the NGINX_PATH variable";
	exit
fi

MODULE_PATH=$(pwd)/;
CONFIG_ARGS=$(nginx -V 2>&1 | tail -n 1 | cut -c 21- | sed -e 's/--add-dynamic-module=.*//g');
CONFIG_ARGS="${CONFIG_ARGS} --add-dynamic-module=${MODULE_PATH}";

# Uncomment to compile with address sanitizer:
#CONFIG_ARGS="${CONFIG_ARGS} --with-cc-opt='-O1 -g -fsanitize=address -fno-omit-frame-pointer' --with-ld-opt='-g -fsanitize=address'";
# Remember to run nginx with LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8 ASAN_OPTIONS=detect_leaks=0

echo "$CONFIG_ARGS";

cd "${NGINX_PATH}";
#bash -c "./configure ${CONFIG_ARGS}"; # you can comment this out in subsequent builds
make modules -j "$(nproc)";

echo "Load the dynamic module ${NGINX_PATH}/objs/ngx_http_shapow_module.so and restart nginx to install";
