import asyncdispatch, ../asyncdocker, json, os

const 
  hostname = "127.0.0.1"
  port = Port(2376)
  ca = joinPath(getHomeDir(), ".docker", "ca.pem")
  key = joinPath(getHomeDir(), ".docker", "key.pem")
  cert = joinPath(getHomeDir(), ".docker", "cert.pem")

proc main() {.async.} =
  var docker = newAsyncDocker(hostname, port, ca, key, cert)
  echo await docker.ps()

waitFor main()

