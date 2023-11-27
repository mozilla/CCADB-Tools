# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Build stage
FROM golang:bookworm AS builder
WORKDIR /go/src/github.com/mozilla/CCADB-Tools/certViewer/
COPY . .
RUN go build -o certViewer ./cmd/web

# Final image
FROM debian:bookworm-slim
WORKDIR /app/

COPY --from=builder /go/src/github.com/mozilla/CCADB-Tools/certViewer/certViewer ./
COPY ./ui ./ui
CMD ["/app/certViewer"]