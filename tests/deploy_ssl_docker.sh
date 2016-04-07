#! /bin/sh
#
# Author: Wang Tong
# Date: 2016-3-28
# Description: base tls keys and certs

# If you want to deploy your docker daemon on tls, please modify these
# params for your environment. 
CAHOST=192.168.199.181
HOST=127.0.0.1
USER=king

set -e

[ $(id -u) != 0 ] && echo "Permission denied" && exit 1

[ -e /home/$USER/.docker ] || mkdir /home/$USER/.docker
cd /home/$USER/.docker

echo "Generating tls keys and certs ..."

openssl genrsa -out ca-key.pem 4096 # openssl genrsa -aes256 -out ca-key.pem 4096 -- needs reply
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -subj "/CN=$CAHOST" -out ca.pem

openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=$HOST" -sha256 -new -key server-key.pem -out server.csr
echo subjectAltName = IP:$HOST > extfile.cnf
openssl x509 -req -days 365 -sha256 -in server.csr      \
                  -CA ca.pem                            \
                  -CAkey ca-key.pem                     \
                  -CAcreateserial                       \
                  -out server-cert.pem                  \
                  -extfile extfile.cnf 

openssl genrsa -out key.pem 4096
openssl req -subj '/CN=client' -new -key key.pem -out client.csr
echo extendedKeyUsage = clientAuth > extfile.cnf
openssl x509 -req -days 365 -sha256 -in client.csr      \
                  -CA ca.pem                            \
                  -CAkey ca-key.pem                     \
                  -CAcreateserial                       \
                  -out cert.pem                         \
                  -extfile extfile.cnf

rm ca.srl server.csr client.csr extfile.cnf

chown $USER:docker ca.pem ca-key.pem server-key.pem server-cert.pem key.pem cert.pem

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
DOCKER_OPTS='--host 0.0.0.0:2376 \
             --tlsverify \
             --tlscacert=/home/${USER}/.docker/ca.pem \
             --tlscert=/home/${USER}/.docker/server-cert.pem \
             --tlskey=/home/${USER}/.docker/server-key.pem'

# If you need Docker to use an HTTP proxy, it can also be specified here.
#export http_proxy=http://127.0.0.1:3128

# This is also a handy place to tweak where Docker temporary files go.
#export TMPDIR=/mnt/bigdrive/docker-tmp
" | cat > /etc/default/docker

echo "Restarting docker daemon ..."

service docker stop
service docker start

export DOCKET_HOST=127.0.0.1:2376
export DOCKER_TLS_VERIFY=1

echo "Complete ."

