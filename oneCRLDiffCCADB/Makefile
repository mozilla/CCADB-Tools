# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

clean:
	-docker stop onecrldiffccadb
	-docker rm onecrldiffccadb
	-docker rmi onecrldiffccadb
	-docker image prune -f
	-docker image prune -f --filter label=stage=intermediate

build:
	docker build --rm -t onecrldiffccadb:latest .
	docker image prune -f
	docker image prune -f --filter label=stage=intermediate

run:
	./run.sh