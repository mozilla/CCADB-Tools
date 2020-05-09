# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

clean:
	-docker stop kintointegrity
	-docker rm kintointegrity
	-docker rmi kintointegrity
	-docker image prune -f
	-docker image prune -f --filter label=stage=intermediate

build:
	docker run --rm -v $(shell pwd):/opt rustlang/rust:nightly cargo build --release --target-dir /opt/target/prod --manifest-path /opt/Cargo.toml
	mkdir -p target/prod/release/artifact
	cp target/prod/release/kinto_integrity target/prod/release/artifact
	docker build --rm -t kintointegrity:latest -f Dockerfile target/prod/release/artifact
	docker image prune -f
	docker image prune -f --filter label=stage=intermediate

update:
	git checkout master
	git pull

deploy:
	make build
	docker run --name kintointegrity -d -e "PORT=80" -e "ENV=PROD" --network host kintointegrity

run:
	./run.sh