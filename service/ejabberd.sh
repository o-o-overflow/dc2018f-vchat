#!/bin/sh
set -e
docker inspect ejabberd >/dev/null && docker kill ejabberd
# FIXME do not expose manage console in production
# docker run --rm --name ejabberd -d -v $(pwd)/ejabberd.yml:/home/ejabberd/conf/ejabberd.yml ejabberd/ecs
docker run --rm --name ejabberd -d -p 5222:5222 -v $(pwd)/ejabberd.yml:/home/ejabberd/conf/ejabberd.yml ejabberd/ecs
sleep 5
docker exec -it ejabberd bin/ejabberdctl register admin ooo.vchat passw0rd
