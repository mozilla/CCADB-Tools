#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Mappings from the host port to the container port.
HOST_PORT=8080
CONTAINER_PORT=80

docker run \
    --name certificate \
    -d \
    -e "PORT=$CONTAINER_PORT" \
        -p ${HOST_PORT}:${CONTAINER_PORT} \
    certificate

