# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
# This is necessary to statically compile all
# C libraries into the executable. Otherwise
# the Alpine installation will fail out with
# a "no such directory" when attempting to execute
# the binary (it can't find the shared libs).
ENV CGO_ENABLED=0
RUN apt-get update
RUN apt-get install -y libnss3-tools libssl-dev ruby-dev
RUN go build capi.go
RUN git clone https://github.com/christopher-henderson/x509lint.git && \
    cd x509lint && \
    make
#RUN git clone https://github.com/kroeckx/x509lint.git && \
#    cd x509lint && \
#    make

FROM alpine:latest

RUN apk add --update nss-tools bash libressl musl libressl ruby
ENV LD_LIBRARY_PATH /lib

# x509lint needs glibc around as well as musl
RUN apk --no-cache add ca-certificates wget
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk
RUN apk add glibc-2.35-r1.apk

RUN apk add git build-base libffi-dev ruby-rdoc ruby-dev
RUN gem install public_suffix simpleidn
RUN cd /tmp && git clone https://github.com/certlint/certlint.git && \
    cd certlint/ext && \
    ruby extconf.rb && \
    make
RUN apk del git build-base libffi-dev ruby-rdoc ruby-dev

COPY --from=buildStage /opt/ /tmp/
RUN mv /tmp/capi /opt/
RUN mv /tmp/certlint /opt/
RUN mv /tmp/x509lint/x509lint /usr/local/bin/
RUN rm -rf /tmp/*

CMD ["/opt/capi"]