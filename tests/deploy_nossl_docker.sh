#! /bin/sh
#
# Author: Wang Tong
# Date: 2016-3-28
# Description: base tls keys and certs

# If you want to deploy your docker daemon on no tls, please modify these
# params for your environment. 
HOST=127.0.0.1
USER=king

set -e

[ $(id -u) != 0 ] && echo "Permission denied" && exit 1

[ -e /home/$USER/.docker ] || mkdir /home/$USER/.docker
cd /home/$USER/.docker

echo "Configuring docker daemon ..."

[ -e /etc/default/docker ] || touch /etc/default/docker
echo "
# Docker Upstart and SysVinit configuration file

#
# THIS FILE DOES NOT APPLY TO SYSTEMD
#
#   Please see the documentation for 'systemd drop-ins':
#   https://docs.docker.com/engine/articles/systemd/
#

# Customize location of Docker binary (especially for development testing).
#DOCKER=/usr/local/bin/docker

# Use DOCKER_OPTS to modify the daemon startup options.
DOCKER_OPTS='--host 0.0.0.0:2375'

# If you need Docker to use an HTTP proxy, it can also be specified here.
#export http_proxy=http://127.0.0.1:3128

# This is also a handy place to tweak where Docker temporary files go.
#export TMPDIR=/mnt/bigdrive/docker-tmp
" | cat > /etc/default/docker

echo "Restarting docker daemon ..."

service docker stop
service docker start

export DOCKET_HOST=127.0.0.1:2375
unset DOCKER_TLS_VERIFY

echo "Complete ."

