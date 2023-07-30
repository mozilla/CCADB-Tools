# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:bookworm AS buildStage

WORKDIR /opt
COPY . .
RUN go build .

FROM debian:bookworm-slim

COPY --from=buildStage /opt/ /opt/

CMD ["/opt/certificate"]