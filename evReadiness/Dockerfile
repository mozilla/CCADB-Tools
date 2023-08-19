# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Build stage
FROM golang:bookworm AS builder
WORKDIR /go/src/github.com/mozilla/CCADB-Tools/evReadiness/
COPY . .
RUN go build -o evReadiness .

# Build ev-checker
RUN apt update && \
    apt install -y clang libcurl4-nss-dev libnspr4-dev libnss3-dev gnutls-bin && \
    cd src && \
    make

# Final image
FROM debian:bookworm-slim
WORKDIR /app/

RUN apt update && \
    apt install -y libcurl4-nss-dev libnss3-dev

COPY --from=builder /go/src/github.com/mozilla/CCADB-Tools/evReadiness/evReadiness ./
COPY --from=builder /go/src/github.com/mozilla/CCADB-Tools/evReadiness/src/ev-checker ./
COPY ./static ./static
COPY ./templates ./templates
CMD ["/app/evReadiness"]