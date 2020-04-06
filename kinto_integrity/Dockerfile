# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM rustlang/rust:nightly AS buildStage

WORKDIR /opt
COPY . .
RUN wget https://dl.google.com/go/go1.13.4.linux-amd64.tar.gz
RUN tar zxf go1.13.4.linux-amd64.tar.gz
RUN ln -s $(pwd)/go/bin/go /usr/local/bin/go
RUN cargo build

FROM ubuntu:latest
RUN apt-get update
RUN apt-get install xvfb libssl-dev ca-certificates libgtk-3-0 libdbus-glib-1-2 -y
RUN apt-get clean

COPY --from=buildStage /opt/target/debug/kinto_integrity /opt/

ENTRYPOINT ["/opt/kinto_integrity"]
