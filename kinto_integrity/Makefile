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
	docker build --rm -t kintointegrity:latest .
	docker image prune -f
	docker image prune -f --filter label=stage=intermediate

update:
	git checkout master
	git pull

deploy:
	make build
	docker run --name kintointegrity -d -e "PORT=80" -p 80:80 kintointegrity

run:
	./run.sh