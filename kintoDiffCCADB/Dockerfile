# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM rustlang/rust:nightly AS buildStage

WORKDIR /opt
COPY . .
RUN cargo build --release

FROM centos:latest
RUN yum install -y bzip2 gtk3 libXt Xvfb
RUN yum clean all

COPY --from=buildStage /opt/target/release/kintoDiffCCADB /opt/

CMD ["Xvfb", ":99"]
ENTRYPOINT ["/opt/kintoDiffCCADB"]