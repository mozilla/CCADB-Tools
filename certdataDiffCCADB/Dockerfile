# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
ENV CGO_ENABLED=0
RUN go build -o certdataDiffCCADB main.go

FROM alpine:latest
RUN apk --update add ca-certificates
COPY --from=buildStage /opt/ /opt/

CMD ["/opt/certdataDiffCCADB", "--serve"]