# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FROM golang:latest AS buildStage

WORKDIR /opt
COPY . .
RUN apt update
RUN apt install -y libnss3-tools libssl-dev ruby-dev
RUN go build capi.go

RUN cd x509lint && \
    make
#RUN git clone https://github.com/kroeckx/x509lint.git && \
#    cd x509lint && \
#    make

FROM debian:latest

RUN apt update
RUN apt install -y gcc g++ git libffi-dev libnss3-tools make ruby-dev ruby-sdoc

RUN gem install public_suffix simpleidn
RUN cd /tmp && git clone https://github.com/certlint/certlint.git && \
    cd certlint/ext && \
    ruby extconf.rb && \
    make

RUN apt purge -y gcc g++ git libffi-dev make ruby-dev ruby-sdoc

COPY --from=buildStage /opt/ /tmp/
RUN mv /tmp/capi /opt/
RUN mv /tmp/certlint /opt/
RUN mv /tmp/x509lint/x509lint /usr/local/bin/
RUN rm -rf /tmp/*

CMD ["/opt/capi"]