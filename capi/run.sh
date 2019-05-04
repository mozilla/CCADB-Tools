#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Mappings from the host port to the container port.
HOST_PORT=8080
CONTAINER_PORT=80

# Mappings from host directory to container directory
# for persisting logs.
HOST_LOG_DIR=$(pwd)/logs/capi
CONTAINER_LOG_DIR=/var/logs/capi/capi.log
mkdir -p ${HOST_LOG_DIR}

# Valid log levels are...
#    panic
#    fatal
#    error
#    warn OR warning
#    info
#    debug
#    trace
# Default is info.
LOGLEVEL=info

# Lumberjack configurations
# In megabytes
MAX_LOG_SIZE=12
# In days
MAX_LOG_AGE=31
MAX_LOG_BACKUPS=12

docker run \
    --name capi \
    -d \
    -e "PORT=$CONTAINER_PORT" \
        -p ${HOST_PORT}:${CONTAINER_PORT} \
    -e "LOG_DIR=$CONTAINER_LOG_DIR" \
        --mount type=bind,source=${HOST_LOG_DIR},target=${CONTAINER_LOG_DIR} \
    -e "MAX_LOG_SIZE=${MAX_LOG_SIZE}" \
    -e "MAX_LOG_AGE=${MAX_LOG_AGE}" \
    -e "MAX_LOG_BACKUPS=${MAX_LOG_BACKUPS}" \
    capi

