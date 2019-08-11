# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM rustlang/rust:nightly AS buildStage

WORKDIR /opt
COPY . .
RUN cargo build --release

FROM ubuntu:latest
RUN apt-get update
RUN apt-get install xvfb libssl-dev ca-certificates libgtk-3-0 libdbus-glib-1-2 -y
RUN apt-get clean

COPY --from=buildStage /opt/target/release/kinto_integrity /opt/

ENTRYPOINT ["/opt/kinto_integrity"]