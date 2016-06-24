import asyncdispatch, ../asyncdocker, json, os

const 
  hostname = "192.168.0.114"
  port = Port(2376)
  certs = "/home/king/Doing/rock/cloudagent/profile/robot/certs"
  ca = joinPath(certs, "ca.pem")
  key = joinPath(certs, "key.pem")
  cert = joinPath(certs, "cert.pem")

proc main() {.async.} =
  var docker = newAsyncDocker(hostname, port, ca, key, cert)
  echo await docker.ps()

waitFor main()

