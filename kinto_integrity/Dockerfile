# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM rustlang/rust@sha256:fdac35b8baebbc8bf1b99919271443688e9ef5656aeda52961edc266dd7f92f8 AS buildStage

WORKDIR /opt
COPY . .
RUN cargo build
RUN wget https://dl.google.com/go/go1.13.4.linux-amd64.tar.gz
RUN tar zxf go1.13.4.linux-amd64.tar.gz
RUN go/bin/go build -o consultant consultant.go

FROM ubuntu:latest
RUN apt-get update
RUN apt-get install xvfb libssl-dev ca-certificates libgtk-3-0 libdbus-glib-1-2 libnvidia-compute-418 libnvidia-gl-418  -y
RUN apt-get clean

COPY --from=buildStage /opt/target/debug/kinto_integrity /opt/
COPY --from=buildStage /opt/consultant /opt/

ENTRYPOINT ["/opt/kinto_integrity"]
