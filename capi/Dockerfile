# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS builder
ENV CGO_ENABLED=0

WORKDIR /opt
COPY . .
RUN go build capi.go

FROM debian:latest

RUN apt update
RUN apt install -y ca-certificates

COPY --from=builder /opt/ /tmp/
RUN mv /tmp/capi /opt/
RUN rm -rf /tmp/*

CMD ["/opt/capi"]
