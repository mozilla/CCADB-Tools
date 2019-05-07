# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

.PHONY: clean
clean:
	-docker stop certdatadiffccadb
	-docker rm certdatadiffccadb
	-docker rmi certdatadiffccadb
	-docker image prune -f
	-docker image prune -f --filter label=stage=intermediate

.PHONY: build
build:
	docker build --rm -t certdatadiffccadb:latest .
	docker image prune -f
	docker image prune -f --filter label=stage=intermediate

.PHONY: run
run:
	# If the container exists, then;
	#	Check to see if it is running
	#		If running; then no-op
	#		Else; start
	# If it does not exist, then;
	# 	Start the container with the default port mapping of 8080 -> 80 and name of certdatadiffccadb
	( \
		docker container inspect certdatadiffccadb > /dev/null 2>&1 && ( \
			docker top certdatadiffccadb > /dev/null 2>&1 || docker start certdatadiffccadb) \
	) \
	|| docker run --name certdatadiffccadb -d -e "PORT=80" -p 8080:80 certdatadiffccadb