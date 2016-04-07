#
#          Nim's Unofficial Library
#        (c) Copyright 2016 Wang Tong
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements an Docker Engine client based on Docker Remotet API. It's
## asynchronous (non-blocking) that it can be used to write web services for deploying
## swarm cluster and containers automatically on cloud environment. Of course, it
## can also be used to write any local deployment tools.
## 
## Docker cli vs asyncdocker 
## =========================
## 
## The docker cli example:
##
## .. code-block:: sh
## 
##   export DOCKER_HOST=127.0.0.1:2375
##   docker create --name hello --hostname 192.168.0.1 \
##                 ubuntu:14.04 /bin/bash -c 'echo hello'
##   docker start hello
##
## And the equivalent asyncdocker example:
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, json
##
##   proc main() {.async.} = 
##     var docker = newAsyncDocker("127.0.0.1", 2375)
##     var ret = await docker.create(image = "ubuntu:14.04", 
##                                   name = "hello",
##                                   hostname = "192.168.0.1",
##                                   cmd = @["/bin/bash", "-c", "echo", "hello"])
##     echo "Container Id: ", ret["Id"].getStr()
##     await docker.start(name = "hello")
##     docker.close()
##
##   waitFor main()
##
## Simulate pull image
## ===================
##
## This example simulates the docker cli ``docker pull ubuntu:14.10`` to download
## the image and print progress bars:
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, json
##
##   const
##     hostname = "127.0.0.1"
##     port = Port(2375)
##
##   proc main() {.async.} =
##     var docker = newAsyncDocker(hostname, port)
##     await docker.pull(fromImage = "ubuntu", tag = "14.10",
##                       cb = proc(state: JsonNode): bool = 
##                         if state.hasKey("progress"):
##                           let current = state["progressDetail"]["current"].getNum()
##                           let total = state["progressDetail"]["total"].getNum()
##                           stdout.write("\r")
##                           stdout.write(state["id"].getStr())
##                           stdout.write(": ")
##                           stdout.write(state["status"].getStr())
##                           stdout.write(" ")
##                           stdout.write($current & "/" & $total)
##                           stdout.write(" ")
##                           stdout.write(state["progress"].getStr())
##                           if current == total:
##                             stdout.write("\n")
##                           stdout.flushFile()
##                         else:
##                           if state.hasKey("id"):
##                             stdout.write(state["id"].getStr())
##                             stdout.write(": ")
##                             stdout.write(state["status"].getStr())
##                             stdout.write("\n")
##                           else: 
##                             stdout.write(state["status"].getStr())
##                             stdout.write("\n"))
##                      
##     docker.close()
##
##   waitFor main()
##
## output:
##
## .. code-block:: nim
##
##   14.10: Pulling from library/ubuntu
##   b0efe5c05b4c: Pulling fs layer
##   0a1f1b169319: Pulling fs layer
##   1ceb0a3c7c48: Pulling fs layer
##   a3ed95caeb02: Pulling fs layer
##   a3ed95caeb02: Waiting
##   1ceb0a3c7c48: Downloading 682/682 [==================================================>]    682 B/682 B
##   1ceb0a3c7c48: Verifying Checksum
##   1ceb0a3c7c48: Download complete
##   a3ed95caeb02: Downloading 32/32 [==================================================>]     32 B/32 BB/77.8 kB
##   a3ed95caeb02: Verifying Checksum
##   a3ed95caeb02: Download complete
##   0a1f1b169319: Downloading 77797/77797 [==================================================>]  77.8 kB/77.8 kB
##   0a1f1b169319: Verifying Checksum
##   0a1f1b169319: Download complete
##   b0efe5c05b4c: Downloading 4848810/68321236 [===>                                               ] 4.849 MB/68.32 MB
##
## Web service
## ===========
##
## You can write a web service with ``asynchttpserver``:
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, asynchttpserver, json
##
##   var server = newAsyncHttpServer()
##
##   proc cb(req: Request) {.async.} =
##     var docker = newAsyncDocker("127.0.0.1", 2375)
##     try:
##       var ret = await docker.create(image = "ubuntu:14.04", 
##                                     name = "hello",
##                                     hostname = "192.168.0.1",
##                                     cmd = @["/bin/bash", "-c", "echo", "hello"])
##       echo "Container Id: ", ret["Id"].getStr()
##       await docker.start(name = "hello")
##       await req.respond(Http201, "OK")
##     except:
##       await req.respond(Http500, "Failure")
##     docker.close()
##
##   waitFor server.serve(Port(8080), cb)
##
## or with ``jester``:
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, asynchttpserver, json, jester
##
##   routes:
##     post "/containers/@name/run"
##       var docker = newAsyncDocker("127.0.0.1", 2375)
##       try:
##         var ret = await docker.create(image = "ubuntu:14.04", 
##                                       name = @"name",
##                                       hostname = "192.168.0.1",
##                                       cmd = @["/bin/bash", "-c", "echo", "hello"])
##         echo "Container Id: ", ret["Id"].getStr()
##         await docker.start(name = "hello")
##         await req.respond(Http201, "OK")
##       except:
##         await req.respond(Http500, "Failure")
##       docker.close()
##
## Stream support
## ==============
##
## Supports to stream responses from the docker daemon with ``attach``, ``logs``, 
## ``execStart``, etc. For example:
##
## .. code-block:: nim
##
##   docker logs --follow hello
##
## .. code-block:: nim
##
##   var i = 0
##   await docker.logs("hello", follow = true, 
##                     cb = proc(stream: int, log: string) = 
##                       if stream == 1:
##                         stdout.write("stdout: " & log)
##                       if stream == 2:
##                         stderr.write("stderr: " & log)
##                       inc(i))
##   echo "recv " & i & " logs"
## 
## Tls verify
## ==========
##
## Supports `--tls` and `--tlsverify` to protect docker daemon socket. 
##
## This requires the OpenSSL library, fortunately it's widely used and installed on 
## many operating systems. Client will use SSL automatically if you give any of 
## the functions a url with the ``https`` schema, for example: ``https://github.com/``,
## you also have to compile with ``ssl`` defined like so: ``nim c -d:ssl ...``.   
##
## For `--tls` verification: 
##
## .. code-block:: sh
##
##   docker --host 127.0.0.1:2376 \
##          --tls \
##          --tlskey /home/docker/.docker/key.pem \
##          --tlscert /home/docker/.docker/cert.pem \
##          ps
## 
## equivalent to: 
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, json, openssl
##
##   const
##     key = "/home/docker/.docker/key.pem"
##     cert = "/home/docker/.docker/cert.pem"
##   
##   proc main() {.async.}
##     var docker = newAsyncDocker("127.0.0.1", 2376, nil, key, cert, CVerifyNone)
##     var containers = await docker.ps()  
##
##   waitFor main()
##
## For `--tlsverify` verification: 
##
## .. code-block:: sh
##
##   docker --host 127.0.0.1:2376 \
##          --tlsverify \
##          --tlscacert /home/docker/.docker/ca.pem \
##          --tlskey /home/docker/.docker/key.pem \
##          --tlscert /home/docker/.docker/cert.pem \
##          ps
## 
## equivalent to: 
##
## .. code-block:: nim
##
##   import asyncdocker, asyncdispatch, json, openssl
##
##   const
##     cacert = "/home/docker/.docker/ca.pem"
##     key = "/home/docker/.docker/key.pem"
##     cert = "/home/docker/.docker/cert.pem"
##   
##   proc main() {.async.}
##     var docker = newAsyncDocker("127.0.0.1", 2376, cacert, key, cert, CVerifyPeer)
##     var containers = await docker.ps()
##
##   waitFor main()
##
## Swarm cluster support
## =====================
##
## The Docker Swarm API is mostly compatible with the Docker Remote API. see `Docker Swarm Reference <https://docs.docker.com/swarm/swarm-api/>`_

import asyncdispatch, asynchttpclient, strutils, json, strtabs, uri, net
import math, nre, base64

when defined(ssl):
  import openssl

type
  AsyncDocker* = ref object ## Asynchronous docker client.
    scheme: string
    hostname: string
    port: string
    httpclient: AsyncHttpClient

  ContainerStatus* = enum ## Enumeration of all container status.
    statCreated, statRestarting, statRunning, statPaused, statExited

  RestartPolicy* = enum ## Enumeration of all restart policy for container.  
    rpNo = "no", rpOnFailure = "on-failure", 
    rpAlways = "always", rpUnlessStopped = "unless-stopped"

  LogType* = enum ## Enumeration of all available log driver.
    logNone = "none", logJsonFile = "json-file", logJournald = "journald",
    logGelf = "gelf", logAwslogs = "awslogs", logSplunk = "splunk"

  DockerError* = object of IOError            ## Requesting to docker daemon has
                                              ## an error.
  NotModifiedError* = object of DockerError   ## `Not modified` from docker daemon,
                                              ## response status code is `304`.
  BadParameterError* = object of DockerError  ## `Bad parameter` from docker daemon,
                                              ## response status code is `400`.
  ForbiddenError* = object of DockerError     ## `Forbidden` from docker daemon, 
                                              ## response status code is `403`.
  NotFoundError* = object of DockerError      ## `Not found` from docker daemon, 
                                              ## response status code is `404`.
  NotAcceptableError* = object of DockerError ## `Not acceptable` from docker daemon,
                                              ## response status code is `406`.                                          
  ConflictError* = object of DockerError      ## `Conflict` from docker daemon,
                                              ## response status code is `409`.
  ServerError* = object of DockerError        ## `Server error` from docker daemon,
                                              ## response status code is `500`.
const 
  dockerVersion* = "1.22"
  userAgent* = "Nim Docker client/0.0.1 (1.22)"

proc add(queries: var seq[string]; name, val: string) =
  add(queries, name & "=" & val)

template parseUriImpl() {.dirty.} =
  result = initUri()
  result.scheme = scheme
  result.hostname = hostname
  result.port = port
  result.path = path

proc parseUri(scheme, hostname, port, path: string): Uri =
  parseUriImpl()

proc parseUri(scheme, hostname, port, path: string; 
              queries: openarray[string]): Uri =
  parseUriImpl()
  result.query = join(queries, "&")

when defined(ssl):
  proc newAsyncDocker*(hostname: string; port: Port; 
                       cacert, key, cert: string = nil;
                       verifyMode = CVerifyPeer): AsyncDocker =
    ## Creates a new AsyncDocker instance. 
    new(result)
    result.hostname = hostname
    result.port = $int(port)
    result.scheme = "https"
    var ctx = newContext(protTLSv1, verifyMode, cert, key) 
    if verifyMode == CVerifyPeer and 
       SSLCTXLoadVerifyLocations(SslCtx(ctx), cacert, nil) != 1:
      raise newException(SSLError, "invalid ca certificate")
    result.httpclient = newAsyncHttpClient(userAgent, ctx)
else:
  proc newAsyncDocker*(hostname: string; port: Port): AsyncDocker =
    ## Creates a new AsyncDocker instance. 
    new(result)
    result.hostname = hostname
    result.port = $int(port)
    result.scheme = "http"
    result.httpclient = newAsyncHttpClient(userAgent)  

proc close*(c: AsyncDocker) =
  ## Closes the socket resource used by ``c``.
  close(c.httpclient)

proc request(c: AsyncDocker, httpMethod: HttpMethod, url: Uri, 
             headers: StringTableRef = nil, body: string = nil,
             cb: Callback = nil): Future[Response] {.async.} =
  try:
    result = await request(c.httpclient, substr($httpMethod, len("http")), 
                           url, headers, body, cb)
  except:
    raise newException(ServerError, getCurrentExceptionMsg())

proc add(x: var JsonNode, key: string, list: seq[string]) = 
  var j = newJArray()
  for i in list:
    add(j, %i)
  add(x, key, j)

proc add(x: var JsonNode, key: string, list: seq[tuple[key, value: string]]) = 
  var j = newJObject()
  for i in list:
    add(j, i.key, %i.value)
  add(x, key, j)

proc parseVnd(cb: proc(stream: int, payload: string): bool): Callback = 
  var buff: array[8, char]
  var buffPos = 0
  var size = -1
  var payload: string
  var payloadPos = 0
  var stream = 0
  proc callback(chunk: string): bool = 
    var le = len(chunk)
    var i = 0
    while i < le:
      if buffPos < 8:
        buff[buffPos] = chunk[i]
        inc(buffPos)
        inc(i)
      elif size == -1:
        stream = int(buff[0])
        size = int(buff[4]) * 16 * 16 * 16 + int(buff[5]) * 16 * 16 +
               int(buff[6]) * 16 + int(buff[7])
        payload = newString(size)
        payloadPos = 0
      elif payloadPos < size:
        payload[payloadPos] = chunk[i]
        inc(i)
        inc(payloadPos)
      else:
        break
    if payloadPos == size:
      buffPos = 0
      size = -1
      result = cb(stream, payload)

  return callback

proc ps*(c: AsyncDocker, 
         all = false, 
         size = false, 
         limit = -1, 
         since = "", 
         before = "", 
         exitedFilters: seq[int] = nil, 
         statusFilters: seq[ContainerStatus] = nil, 
         labelFilters: seq[string] = nil): Future[JsonNode] {.async.} =
  ## List containers. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#list-containers>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``BadParameterError``, ``ServerError``
  ## or ``DockerError``.  
  ##
  ## Request parameters:
  ##
  ## * ``all`` - Show all containers. Only running containers are shown by default 
  ##   (i.e., this defaults to false).
  ## * ``size`` - Show the containers sizes.
  ## * ``limit`` - Show limit last created containers, include non-running ones.
  ## * ``since`` - Show only containers created since Id, include non-running ones.
  ## * ``before`` - Show only containers created before Id, include non-running ones. 
  ## * ``exitedFilters`` - Filter containers with exit code.
  ## * ``statusFilters`` - Filter containers with status. Available status: 
  ##   `created` | `restarting` | `running` | `paused` | `exited`.
  ## * ``labelFilters`` - Filter containers with label.  
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. 
  ## For example:
  ##
  ## .. code-block:: nim
  ##
  ##   [
  ##     {
  ##       "Id": "8dfafdbc3a40",
  ##       "Names":["/boring_feynman"],
  ##       "Image": "ubuntu:latest",
  ##       "ImageID": "d74508fb6632491cea586a1fd7d748dfc5274cd6fdfedee309ecdcbc2bf5cb82",
  ##       "Command": "echo 1",
  ##       "Created": 1367854155,
  ##       "Status": "Exit 0",
  ##       "Ports": [{"PrivatePort": 2222, "PublicPort": 3333, "Type": "tcp"}],
  ##       "Labels": {
  ##         "com.example.vendor": "Acme",
  ##         "com.example.license": "GPL",
  ##         "com.example.version": "1.0"
  ##       },
  ##       "SizeRw": 12288,
  ##       "SizeRootFs": 0
  ##     },
  ##     {
  ##       "Id": "9cd87474be90",
  ##       "Names":["/coolName"],
  ##       "Image": "ubuntu:latest",
  ##       "ImageID": "d74508fb6632491cea586a1fd7d748dfc5274cd6fdfedee309ecdcbc2bf5cb82",
  ##       "Command": "echo 222222",
  ##       "Created": 1367854155,
  ##       "Status": "Exit 0",
  ##       "Ports": [],
  ##       "Labels": {},
  ##       "SizeRw": 12288,
  ##       "SizeRootFs": 0
  ##     },
  ##     {
  ##       "Id": "3176a2479c92",
  ##       "Names":["/sleepy_dog"],
  ##       "Image": "ubuntu:latest",
  ##       "ImageID": "d74508fb6632491cea586a1fd7d748dfc5274cd6fdfedee309ecdcbc2bf5cb82",
  ##       "Command": "echo 3333333333333333",
  ##       "Created": 1367854154,
  ##       "Status": "Exit 0",
  ##       "Ports":[],
  ##       "Labels": {},
  ##       "SizeRw":12288,
  ##       "SizeRootFs":0
  ##     },
  ##     {
  ##       "Id": "4cb07b47f9fb",
  ##       "Names":["/running_cat"],
  ##       "Image": "ubuntu:latest",
  ##       "ImageID": "d74508fb6632491cea586a1fd7d748dfc5274cd6fdfedee309ecdcbc2bf5cb82",
  ##       "Command": "echo 444444444444444444444444444444444",
  ##       "Created": 1367854152,
  ##       "Status": "Exit 0",
  ##       "Ports": [],
  ##       "Labels": {},
  ##       "SizeRw": 12288,
  ##       "SizeRootFs": 0
  ##     }
  ##   ]
  ##
  ## If you access the docker swarm api, the result will has new field
  ## ``Node`` added:
  ##
  ## .. code-block:: nim
  ##
  ##     "Node": {
  ##       "Id": "ODAI:IC6Q:MSBL:TPB5:HIEE:6IKC:VCAM:QRNH:PRGX:ERZT:OK46:PMFX",
  ##       "Ip": "0.0.0.0",
  ##       "Addr": "http://0.0.0.0:4243",
  ##       "Name": "vagrant-ubuntu-saucy-64",
  ##     },
  ##
  ## see `Docker Reference of Swarm API <https://docs.docker.com/swarm/swarm-api/#endpoints-which-behave-differently>`_
  var queries: seq[string] = @[]
  if all:
    add(queries, "all", "1")
  if size:
    add(queries, "size",  "1")
  if limit > -1:
    add(queries, "limit", $limit)
  if since != nil and since != "":
    add(queries, "since",  since)
  if before != nil and before != "":
    add(queries, "before",  before)
  var filters = newJObject()
  if exitedFilters != nil:
    var exiteds = newJArray()
    for flt in exitedFilters:
      add(exiteds, newJString($flt))
    add(filters, "exited", exiteds)
  if statusFilters != nil:  
    var statuses = newJArray()
    for flt in statusFilters:
      add(statuses, newJString(toLower(substr($flt, 4))))
    add(filters, "status", statuses)
  if labelFilters != nil: 
    var labels = newJArray()
    for flt in labelFilters:
      add(labels, newJString(flt)) 
    add(filters, "label", labels)
  add(queries, "filters", $filters)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/json", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 400:
    raise newException(BadParameterError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc create*(c: AsyncDocker; 
             image: string;
             cmd, entrypoint: seq[string] = nil;
             name, hostname, domainname, user = "";
             attachStdin, attachStdout, attachStderr = true;
             tty, openStdin, stdinOnce = false;
             labels: seq[tuple[key, value: string]] = nil;
             workingDir, macAddress = "";
             stopSignal = "SIGTERM";
             networkDisabled = false;
             env, exposedPorts, volumes, binds, links: seq[string] = nil;
             memory, memorySwap, memoryReservation, kernelMemory = 0;
             memorySwappiness = -1;
             cpuShares, cpuPeriod, cpuQuota = 0;
             cpusetCpus, cpusetMems = "";
             blkioWeight = 0;
             blkioWeightDevice: seq[tuple[path: string, weight: int]] = nil,
             blkioDeviceReadBps: seq[tuple[path: string, rate: int]] = nil,
             blkioDeviceWriteBps: seq[tuple[path: string, rate: int]] = nil,
             blkioDeviceReadIOps: seq[tuple[path: string, rate: int]] = nil,
             blkioDeviceWriteIOps: seq[tuple[path: string, rate: int]] = nil,
             oomKillDisable = false,
             oomScoreAdj = 0;
             networkMode = "bridge";
             portBindings: seq[tuple[port: string, hostPort: seq[string]]] = nil,
             publishAllPorts, privileged, readonlyRootfs = false;
             dns, dnsOptions, dnsSearch: seq[string] = nil;
             extraHosts, volumesFrom, capAdd, capDrop: seq[string] = nil;
             restartPolicy: tuple[name: RestartPolicy, maximumRetryCount: int] = (rpNo, 0);
             securityOpt: seq[string] = nil;
             cgroupParent, volumeDriver = "";
             shmSize = 0;
             ulimits: seq[tuple[name: string, soft: int, hard: int]] = nil;
             devices: seq[tuple[pathOnHost, pathInContainer, cgroupPermissions: string]] = nil;
             logConfig: tuple[typ: LogType, config: seq[tuple[key, value: string]]] = (logJsonFile, nil)
             ): Future[JsonNode] {.async.} =
  ## Create a container. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#create-a-container>`_
  ##  
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``NotAcceptableError``, 
  ## ``ServerError`` or ``DockerError``.
  ##
  ## Request parameters:
  ##
  ## * ``image`` - A string specifying the image name to use for the container.
  ## * ``cmd`` - Command to run specified as a string or an array of strings.
  ## * ``name`` - Assign the specified name or id to the container. 
  ##   Must match `/?[a-zA-Z0-9_-]+`.
  ## * ``hostname`` - A string value containing the hostname to use for the container.
  ## * ``domainname`` - A string value containing the domain name to use for the container.
  ## * ``user`` - A string value specifying the user inside the container.
  ## * ``attachStdin`` - Boolean value, attaches to `stdin`.
  ## * ``attachStdout`` - Boolean value, attaches to `stdout`.
  ## * ``attachStderr`` - Boolean value, attaches to `stderr`.
  ## * ``tty`` - Boolean value, Attach standard streams to a `tty`, including `stdin` if it
  ##   is not closed.
  ## * ``openStdin`` - Boolean value, opens stdin. 
  ## * ``stdinOnce`` - Boolean value, close `stdin` after the 1 attached client disconnects.
  ## * ``env`` - A list of environment variables in the form of `@["VAR=value","VAR2=value2"]`.
  ## * ``entrypoint`` - Set the entry point for the container.
  ## * ``labels`` - Adds a map of labels to a container. To specify a map: 
  ##   `{"key":"value", "key2":"value2"}`.
  ## * ``workingDir`` - A string specifying the working directory for commands to run in.
  ## * ``stopSignal`` - Signal to stop a container as a string or unsigned integer. `SIGTERM` 
  ##   by  default.
  ## * ``networkDisabled`` - Boolean value, when true disables networking for the container.
  ## * ``exposedPorts`` - Mapping ports in the form of: `"@["<port>/<tcp|udp>"]`.
  ## * ``volumes`` - A list of volume that you want mount for this container.
  ## * ``binds`` - A list of volume bindings for this container. Each volume binding is a
  ##   string in one of these forms: 
  ##   * `container_path` to create a new volume for the container.
  ##   * `host_path:container_path` to bind-mount a host path into the container.
  ##   * `host_path:container_path:ro` to make the bind-mount read-only inside the container.
  ## * ``links`` - A list of links for the container. Each link entry should be in the  
  ##   form  of `container_name:alias`.
  ## * ``memory`` - Memory limit in bytes.
  ## * ``memorySwap`` - Total memory limit (memory + swap); set `-1` to disable swap.
  ##   You must use this with ``Memory`` and make the swap value larger than ``Memory``.
  ## * ``memoryReservation`` - Memory soft limit in bytes.
  ## * ``kernelMemory`` - Kernel memory limit in bytes.
  ## * ``cpuShares`` - An integer value containing the container’s CPU Shares (ie. the 
  ##   relative weight vs other containers).
  ## * ``cpuPeriod`` - The length of a CPU period in microseconds.
  ## * ``cpuQuota`` - Microseconds of CPU time that the container can get in a CPU period.
  ## * ``cpuset`` - Deprecated please don’t use. Use ``CpusetCpus`` instead.
  ## * ``cpusetCpus`` - String value containing the `cgroups CpusetCpus` to use.
  ## * ``cpusetMems`` - Memory nodes (MEMs) in which to allow execution (0-3, 0,1). Only 
  ##   effective on NUMA systems.
  ## * ``blkioWeight`` - Block IO weight (relative weight) accepts a weight value between 
  ##   10 and 1000.
  ## * ``memorySwappiness`` - Tune a container’s memory swappiness behavior. Accepts an 
  ##   integer between 0 and 100.
  ## * ``blkioWeightDevice`` - Block IO weight (relative device weight) in the form of: 
  ##   `@[("Path": "device_path", "Weight": weight)]`.
  ## * ``blkioDeviceReadBps`` - Limit read rate (bytes per second) from a device in the 
  ##   form of: `@[("Path": "device_path", "Rate": rate)]`.
  ## * ``blkioDeviceWriteBps`` - Limit write rate (bytes per second) to a device in the
  ##   form of: `@[("Path": "device_path", "Rate": rate)]`.
  ## * ``blkioDeviceReadIOps`` - Limit read rate (IO per second) from a device in the 
  ##   form of: `@[("Path": "device_path", "Rate": rate)]`.
  ## * ``blkioDeviceWriteIOps`` - Limit write rate (IO per second) to a device in the
  ##   form of: `@[("Path": "device_path", "Rate": rate)]`.
  ## * ``oomKillDisable`` - Boolean value, whether to disable OOM Killer for the container
  ##   or not.
  ## * ``OomScoreAdj`` - An integer value containing the score given to the container in 
  ##   order to tune OOM killer preferences.
  ## * ``networkMode`` - Sets the networking mode for the container. Supported values are: 
  ##   `bridge`, `host`, and `container:<name|id>`.
  ## * ``portBindings`` - A map of exposed container ports.
  ## * ``publishAllPorts`` - Allocates a random host port for all of a container’s exposed 
  ##   ports.Specified as a boolean value.
  ## * ``privileged`` - Gives the container full access to the host. Specified as a boolean value.
  ## * ``readonlyRootfs`` - Mount the container’s root filesystem as read only. Specified as 
  ##   a boolean value.
  ## * ``dns`` - A list of DNS servers for the container to use.
  ## * ``dnsOptions`` - A list of DNS options.
  ## * ``dnsSearch`` - A list of DNS search domains
  ## * ``extraHosts`` - A list of hostnames/IP mappings to add to the container’s `/etc/hosts` 
  ##   file. Specified in the form `["hostname:IP"]`.
  ## * ``volumesFrom`` - A list of volumes to inherit from another container. Specified in the
  ##   form `<container name>[:<ro|rw>]`.
  ## * ``capAdd`` - A list of kernel capabilities to add to the container.
  ## * ``capdrop`` - A list of kernel capabilities to drop from the container.
  ## * ``restartPolicy`` - The behavior to apply when the container exits. The value is an object
  ##   with a `Name` property of either `"always"` to always restart, `"unless-stopped"` to 
  ##   restart always except when user has manually stopped the container or `"on-failure"` to 
  ##   restart only when the container exit code is non-zero. If `on-failure` is used, `MaximumRetryCount`
  ##   controls the number of times to retry before giving up. The default is not to restart. 
  ##   (optional) An ever increasingdelay (double the previous delay, starting at 100mS) is added 
  ##   before each restart to prevent flooding the server.
  ## * ``securityOpt`` - A list of string values to customize labels for MLS systems, such as SELinux.
  ## * ``cgroupParent`` - Path to `cgroups` under which the container’s `cgroup` is created. If the 
  ##   path is not absolute, the path is considered to be relative to the `cgroups` path of the init 
  ##   process. Cgroups are created if they do not already exist.
  ## * ``volumeDriver`` - Driver that this container users to mount volumes.
  ## * ``ShmSize`` - Size of /dev/shm in bytes. The size must be greater than 0. If omitted the
  ##   system uses 64MB.
  ## * ``ulimits`` - A list of ulimits to set in the container, specified as 
  ##   `( "Name": <name>, "Soft": <soft limit>, "Hard": <hard limit> )`.
  ## * ``devices`` - A list of devices to add to the container specified in the form 
  ##   `( "PathOnHost": "/dev/deviceName", "PathInContainer": "/dev/deviceName", "CgroupPermissions": "mrw")`.
  ## * ``logConfig`` - Log configuration for the container, specified in the form 
  ##   `( "Type": "<driver_name>", "Config": {"key1": "val1"})`. Available types: `json-file`, `syslog`, 
  ##   `journald`, `gelf`, `awslogs`, `none`. `json-file` logging driver.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. 
  ## For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Id":"e90e34656806",
  ##     "Warnings":[]
  ##   }
  ##
  ## **Note:** the official documentation of ``Mounts`` is invalid. Use ``Volumes`` or ``Binds`` 
  ## to mount for your container. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   var ret = await docker.create(image = "ubuntu:14.10",
  ##                                 cmd = @["/bin/bash", "-c", "echo", "hello"],
  ##                                 exposedPorts = @["22/tcp"],
  ##                                 volumes = @["/tmp", "/data"],
  ##                                 portBindings = @[("5000", @["5000"])])
  ##   echo "Container Id: ", ret["Id"].getStr()
  ## 
  ## equivalent to:
  ##
  ## .. code-block:: nim
  ##
  ##   docker create --expose 22/tcp \
  ##                 --volumes /tmp --volumes /store \
  ##                 --publish 5000:5000 \
  ##                 ubuntu:14.10 /bin/bash -c 'echo hello'
  ##
  ## In the above example, docker engine will copy files from `/tmp` and `/data` to container volumes. 
  ##
  ## But following example does not copy (just mounting):
  ##
  ## .. code-block:: nim
  ##
  ##   var ret = await docker.create(image = "ubuntu:14.10",
  ##                                 cmd = @["/bin/bash", "-c", "echo", "hello"],
  ##                                 exposedPorts = @["22/tcp"],
  ##                                 binds = @["/tmp:/tmp:ro", "/store:/data:rw"],
  ##                                 portBindings = @[("5000", @["5000"])])
  ##   echo "Container Id: ", ret["Id"].getStr()
  ## 
  ## equivalent to:
  ##
  ## .. code-block:: nim
  ##
  ##   docker create --expose 22/tcp \
  ##                 --volumes /tmp:/tmp:ro --volumes /store:/data:rw \
  ##                 --publish 5000:5000 \
  ##                 ubuntu:14.10 /bin/bash -c 'echo hello'
  var queries: seq[string] = @[]
  if name != nil and name != "":
    add(queries, "name", name)
  var jBody = newJObject()
  add(jBody, "Image", %image)
  add(jBody, "Cmd", cmd)
  add(jBody, "Hostname", %hostname)
  add(jBody, "Domainname", %domainname)
  add(jBody, "User", %user)
  add(jBody, "AttachStdin", %attachStdin)
  add(jBody, "AttachStdout", %attachStdout)
  add(jBody, "AttachStderr", %attachStderr)
  add(jBody, "Tty", %tty)
  add(jBody, "OpenStdin", %openStdin)
  add(jBody, "StdinOnce", %stdinOnce)
  add(jBody, "Env", env)
  add(jBody, "Entrypoint", entrypoint)
  add(jBody, "Labels", labels)
  add(jBody, "WorkingDir", %workingDir)
  add(jBody, "MacAddress", %macAddress)
  add(jBody, "StopSignal", %stopSignal)
  add(jBody, "NetworkDisabled", %networkDisabled)
  var jExposedPorts = newJObject()
  for i in exposedPorts:
    add(jExposedPorts, i, newJObject())
  add(jBody, "ExposedPorts", jExposedPorts)
  var jVolumes = newJObject()
  for i in volumes:
    add(jVolumes, i, newJObject())
  add(jBody, "Volumes", jVolumes)
  # <HostConfig>
  var jHostConfig = newJObject()
  add(jHostConfig, "Binds", binds)
  add(jHostConfig, "Links", links)
  add(jHostConfig, "Memory", %memory)
  add(jHostConfig, "MemorySwap", %memorySwap)
  add(jHostConfig, "MemoryReservation", %memoryReservation)
  add(jHostConfig, "KernelMemory", %kernelMemory)
  add(jHostConfig, "CpuShares", %cpuShares)
  add(jHostConfig, "CpuPeriod", %cpuPeriod)
  add(jHostConfig, "CpuQuota", %cpuQuota)
  add(jHostConfig, "BlkioWeight", %blkioWeight)
  add(jHostConfig, "CpusetCpus", %cpusetCpus)
  add(jHostConfig, "CpusetMems", %cpusetMems)
  add(jHostConfig, "MemorySwappiness", %memorySwappiness)
  var JBlkioWeightDevice = newJArray()
  for i in blkioWeightDevice:
    var j = newJObject()
    add(j, "Path", %i.path)
    add(j, "Weight", %($i.weight))
    add(JBlkioWeightDevice, j)
  add(jHostConfig, "BlkioWeightDevice", JBlkioWeightDevice)
  var jBlkioDeviceReadBps = newJArray()
  for i in blkioDeviceReadBps:
    var j = newJObject()
    add(j, "Path", %i.path)
    add(j, "Rate", %($i.rate))
    add(jBlkioDeviceReadBps, j)
  add(jHostConfig, "BlkioDeviceReadBps", jBlkioDeviceReadBps)
  var jBlkioDeviceWriteBps = newJArray()
  for i in blkioDeviceWriteBps:
    var j = newJObject()
    add(j, "Path", %i.path)
    add(j, "Rate", %($i.rate))
    add(jBlkioDeviceReadBps, j)
  add(jHostConfig, "BlkioDeviceWriteBps", jBlkioDeviceWriteBps)
  var jBlkioDeviceReadIOps = newJArray()
  for i in blkioDeviceReadIOps:
    var j = newJObject()
    add(j, "Path", %i.path)
    add(j, "Rate", %($i.rate))
    add(jBlkioDeviceReadIOps, j)
  add(jHostConfig, "BlkioDeviceReadIOps", jBlkioDeviceReadIOps)
  var jBlkioDeviceWriteIOps = newJArray()
  for i in blkioDeviceWriteIOps:
    var j = newJObject()
    add(j, "Path", %i.path)
    add(j, "Rate", %($i.rate))
    add(jBlkioDeviceWriteIOps, j)
  add(jHostConfig, "BlkioDeviceWiiteIOps", jBlkioDeviceWriteIOps)
  add(jHostConfig, "OomKillDisable", %oomKillDisable)
  add(jHostConfig, "OomScoreAdj", %oomScoreAdj)
  add(jHostConfig, "NetworkMode", %networkMode)
  var jPortBindings = newJObject()
  for i in portBindings:
    var a = newJArray()
    for n in i.hostPort:
      var b = newJObject()
      add(b, "HostPort", %n)
      add(a, b)
    add(jPortBindings, i.port, a) 
  add(jHostConfig, "PortBindings", jPortBindings)
  add(jHostConfig, "PublishAllPorts", %publishAllPorts)
  add(jHostConfig, "Privileged", %privileged)
  add(jHostConfig, "ReadonlyRootfs", %readonlyRootfs)
  add(jHostConfig, "Dns", dns)
  add(jHostConfig, "DnsOptions", dnsOptions)
  add(jHostConfig, "DnsSearch", dnsSearch)
  add(jHostConfig, "ExtraHosts", extraHosts)
  add(jHostConfig, "VolumesFrom", volumesFrom)
  add(jHostConfig, "CapAdd", capAdd)
  add(jHostConfig, "CapDrop", capDrop)
  var jRestartPolicy = newJObject()
  add(jRestartPolicy, "Name", %($restartPolicy.name))
  add(jRestartPolicy, "MaximumRetryCount", %restartPolicy.maximumRetryCount)
  add(jHostConfig, "RestartPolicy", jRestartPolicy)
  add(jHostConfig, "SecurityOpt", securityOpt)
  add(jHostConfig, "CgroupParent", %cgroupParent)
  add(jHostConfig, "VolumeDrive", %volumeDriver)
  add(jHostConfig, "ShmSize", %shmSize) 
  var jUlimits = newJArray()
  for i in ulimits:
    var j = newJObject()
    add(j, "Name", %i.name)
    add(j, "Soft", %i.soft)
    add(j, "Hard", %i.hard)
    add(jUlimits, j)
  add(jHostConfig, "Ulimits", jUlimits) 
  var jDevices = newJArray()
  for i in devices:
    var j = newJObject()
    add(j, "PathOnHost", %i.pathOnHost)
    add(j, "PathInContainer", %i.pathInContainer)
    add(j, "CgroupPermissions", %i.cgroupPermissions)
    add(jDevices, j)
  add(jHostConfig, "Devices", jDevices)
  var jLogConfig = newJObject()
  var jLogConfigCfg = newJObject()
  for i in logConfig.config:
    var j = newJObject()
    add(jLogConfigCfg, i.key, %i.value)
  add(jLogConfig, "Type", %($logConfig.typ))
  add(jLogConfig, "Config", jLogConfigCfg)
  add(jHostConfig, "LogConfig", jLogConfig)
  # </HostConfig>
  add(jBody, "HostConfig", jHostConfig)
  # echo "------------"
  # echo pretty(jBody)
  # echo "------------"
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/create", queries)
  var headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 201:
    try:
        result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 406:
    raise newException(NotAcceptableError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc inspect*(c: AsyncDocker, name: string, size = false): Future[JsonNode] {.async.} =
  ## Return low-level information on the container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``size`` - Return container size information.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. 
  ## For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##    "AppArmorProfile": "",
  ##    "Args": [
  ##      "-c",
  ##      "exit 9"
  ##    ],
  ##    "Config": {
  ##      "AttachStderr": true,
  ##      "AttachStdin": false,
  ##      "AttachStdout": true,
  ##      "Cmd": [
  ##        "/bin/sh",
  ##        "-c",
  ##        "exit 9"
  ##      ],
  ##      "Domainname": "",
  ##      "Entrypoint": null,
  ##      "Env": [
  ##        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  ##      ],
  ##      "ExposedPorts": null,
  ##      "Hostname": "ba033ac44011",
  ##      "Image": "ubuntu",
  ##      "Labels": {
  ##        "com.example.vendor": "Acme",
  ##        "com.example.license": "GPL",
  ##        "com.example.version": "1.0"
  ##      },
  ##      "MacAddress": "",
  ##      "NetworkDisabled": false,
  ##      "OnBuild": null,
  ##      "OpenStdin": false,
  ##      "StdinOnce": false,
  ##      "Tty": false,
  ##      "User": "",
  ##      "Volumes": null,
  ##      "WorkingDir": "",
  ##      "StopSignal": "SIGTERM"
  ##    },
  ##    "Created": "2015-01-06T15:47:31.485331387Z",
  ##    "Driver": "devicemapper",
  ##    "ExecDriver": "native-0.2",
  ##    "ExecIDs": null,
  ##    "HostConfig": {
  ##      "Binds": null,
  ##      "BlkioWeight": 0,
  ##      "CapAdd": null,
  ##      "CapDrop": null,
  ##      "ContainerIDFile": "",
  ##      "CpusetCpus": "",
  ##      "CpusetMems": "",
  ##      "CpuShares": 0,
  ##      "CpuPeriod": 100000,
  ##      "Devices": [],
  ##      "Dns": null,
  ##      "DnsOptions": null,
  ##      "DnsSearch": null,
  ##      "ExtraHosts": null,
  ##      "IpcMode": "",
  ##      "Links": null,
  ##      "LxcConf": [],
  ##      "Memory": 0,
  ##      "MemorySwap": 0,
  ##      "MemoryReservation": 0,
  ##      "KernelMemory": 0,
  ##      "OomKillDisable": false,
  ##      "NetworkMode": "bridge",
  ##      "PortBindings": {},
  ##      "Privileged": false,
  ##      "ReadonlyRootfs": false,
  ##      "PublishAllPorts": false,
  ##      "RestartPolicy": {
  ##        "MaximumRetryCount": 2,
  ##        "Name": "on-failure"
  ##      },
  ##      "LogConfig": {
  ##        "Config": null,
  ##        "Type": "json-file"
  ##      },
  ##      "SecurityOpt": null,
  ##      "VolumesFrom": null,
  ##      "Ulimits": [{}],
  ##      "VolumeDriver": ""
  ##    },
  ##    "HostnamePath": "/var/lib/docker/containers/ba033ac4401106a3b513bc9d639eee123ad78ca3616b921167cd74b20e25ed39/hostname",
  ##    "HostsPath": "/var/lib/docker/containers/ba033ac4401106a3b513bc9d639eee123ad78ca3616b921167cd74b20e25ed39/hosts",
  ##    "LogPath": "/var/lib/docker/containers/1eb5fabf5a03807136561b3c00adcd2992b535d624d5e18b6cdc6a6844d9767b/1eb5fabf5a03807136561b3c00adcd2992b535d624d5e18b6cdc6a6844d9767b-json.log",
  ##    "Id": "ba033ac4401106a3b513bc9d639eee123ad78ca3616b921167cd74b20e25ed39",
  ##    "Image": "04c5d3b7b0656168630d3ba35d8889bd0e9caafcaeb3004d2bfbc47e7c5d35d2",
  ##    "MountLabel": "",
  ##    "Name": "/boring_euclid",
  ##    "NetworkSettings": {
  ##      "Bridge": "",
  ##      "SandboxID": "",
  ##      "HairpinMode": false,
  ##      "LinkLocalIPv6Address": "",
  ##      "LinkLocalIPv6PrefixLen": 0,
  ##      "Ports": null,
  ##      "SandboxKey": "",
  ##      "SecondaryIPAddresses": null,
  ##      "SecondaryIPv6Addresses": null,
  ##      "EndpointID": "",
  ##      "Gateway": "",
  ##      "GlobalIPv6Address": "",
  ##      "GlobalIPv6PrefixLen": 0,
  ##      "IPAddress": "",
  ##      "IPPrefixLen": 0,
  ##      "IPv6Gateway": "",
  ##      "MacAddress": "",
  ##      "Networks": {
  ##        "bridge": {
  ##          "EndpointID": "",
  ##          "Gateway": "",
  ##          "IPAddress": "",
  ##          "IPPrefixLen": 0,
  ##          "IPv6Gateway": "",
  ##          "GlobalIPv6Address": "",
  ##          "GlobalIPv6PrefixLen": 0,
  ##          "MacAddress": ""
  ##        }
  ##      }
  ##    },
  ##    "Path": "/bin/sh",
  ##    "ProcessLabel": "",
  ##    "ResolvConfPath": "/var/lib/docker/containers/ba033ac4401106a3b513bc9d639eee123ad78ca3616b921167cd74b20e25ed39/resolv.conf",
  ##    "RestartCount": 1,
  ##    "State": {
  ##      "Error": "",
  ##      "ExitCode": 9,
  ##      "FinishedAt": "2015-01-06T15:47:32.080254511Z",
  ##      "OOMKilled": false,
  ##      "Paused": false,
  ##      "Pid": 0,
  ##      "Restarting": false,
  ##      "Running": true,
  ##      "StartedAt": "2015-01-06T15:47:32.072697474Z",
  ##      "Status": "running"
  ##    },
  ##    "Mounts": [
  ##      {
  ##        "Source": "/data",
  ##        "Destination": "/data",
  ##        "Mode": "ro,Z",
  ##        "RW": false
  ##      }
  ##    ]
  ##   }
  var queries: seq[string] = @[]
  if size:
    add(queries, "size", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/json", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc top*(c: AsyncDocker, name: string, psArgs = "-ef"): Future[JsonNode] {.async.} =
  ## List processes running inside the container `name` (name or id). see `Docker Reference<https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#list-processes-running-inside-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, 
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ## 
  ## * ``psArgs`` - Ps arguments to use (e.g., `aux`). 
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Titles": [
  ##       "USER",
  ##       "PID",
  ##       "%CPU",
  ##       "%MEM",
  ##       "VSZ",
  ##       "RSS",
  ##       "TTY",
  ##       "STAT",
  ##       "START",
  ##       "TIME",
  ##       "COMMAND"
  ##     ],
  ##     "Processes": [
  ##       ["root","20147","0.0","0.1","18060","1864","pts/4","S","10:06","0:00","bash"],
  ##       ["root","20271","0.0","0.0","4312","352","pts/4","S+","10:07","0:00","sleep","10"]
  ##     ]
  ##   }
  var queries: seq[string] = @[]
  if psArgs != nil:
    add(queries, "ps_args", psArgs)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/top", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc logs*(c: AsyncDocker; name: string; 
           stdout = true; stderr, follow, timestamps = false; 
           since = 0; tail = "all", cb: proc(stream: int, log: string): bool) {.async.} =
  ## Get `stdout` and `stderr` logs from the container `name` (name or id).
  ## see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-container-logs>`_
  ##
  ## Note: This endpoint works only for containers with the json-file or 
  ## journald logging drivers. 
  ##
  ## Note: one of ``stdout`` and ``stderr`` must be ``true``.
  ##
  ## ``FutureError`` represents an exception, it may be ``BadParameterError``, 
  ## ``NotFoundError``, ``ServerError`` or ``DockerError``.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``follow`` - Return stream. The response will output log for ever. If 
  ##   you want end to outputing, call ``close`` to close the socket used by ``AsyncDocker``.
  ## * ``stdout`` - Show `stdout` log.
  ## * ``stderr`` - Show `stderr` log.
  ## * ``timestamps`` - Print timestamps for every log line.
  ## * ``since`` - UNIX timestamp (integer) to filter logs. Specifying a timestamp 
  ##   will only output log-entries since that timestamp. Default: 0 (unfiltered).
  ## * ``tail`` - Output specified number of lines at the end of logs: `all` or `<number>`.
  ## * ``cb`` - Handles the data from docker daemon. ``stream`` is one of 
  ##   stdin 0, stdout 1, stderr 2; ``log`` is the log data.
  ## 
  ## For example, if you start a container like this:
  ##
  ## .. code-block:: sh
  ## 
  ##   docker run --detach --name my_container ubuntu:14.04 \
  ##              /bin/sh -c "while true; do echo hello world; sleep 1; done"
  ##
  ## then, to get logs from this container like this:
  ##
  ## .. code-block:: nim
  ##
  ##   var i = 0
  ##   await docker.logs("my_container", cb = proc(chunk: string) = 
  ##       echo "Log ", i, ": ", chunk
  ##       inc(i))
  ##   echo "Complete ."
  ##
  ## This will output:
  ##
  ## .. code-block:: nim
  ##
  ##   Log 0: hello world
  ##   Log 1: hello world
  ##   Log 2: hello world
  ##   Complete .
  var queries: seq[string] = @[]
  if follow:
    add(queries, "follow", "1")
  if stdout:
    add(queries, "stdout", "1")
  if stderr:
    add(queries, "stderr", "1")
  if timestamps:
    add(queries, "timestamps", "1")
  if since > 0:
    add(queries, "since", $since)
  add(queries, "tail", tail)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/logs", queries)
  let res = await request(c, httpGET, url, 
                          cb = if cb == nil: nil else: parseVnd(cb))
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc changes*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Inspect changes on container’s filesystem. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-changes-on-a-container-s-filesystem>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, 
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   [
  ##     {
  ##       "Path": "/dev",
  ##       "Kind": 0
  ##     },
  ##     {
  ##       "Path": "/dev/kmsg",
  ##       "Kind": 1
  ##     },
  ##     {
  ##       "Path": "/test",
  ##       "Kind": 1
  ##     }
  ##   ]  
  ## 
  ## Values for `Kind`:
  ##
  ## * `0` - Modify
  ## * `1` - Add
  ## * `2` - Delete
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/changes")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc exportContainer*(c: AsyncDocker, name: string,
                      cb: proc(data: string): bool) {.async.} =
  ## Export the contents of container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#export-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, 
  ## ``ServerError`` or `DockerError`. 
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``cb`` - Handles the data from docker daemon in streaming.
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/export")
  let res = await request(c, httpGET, url, cb = cb)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc stats*(c: AsyncDocker, name: string, stream = false,
            cb: proc(stat: JsonNode): bool) {.async.} =
  ## Returns a live the container’s resource usage statistics.
  ## Note: this functionality currently only works when using the libcontainer 
  ## exec-driver. Note: not support stream mode currently. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-container-stats-based-on-resource-usage>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, 
  ## ``ServerError`` or ``DockerError``.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``stream`` - Pull stats once then disconnect. 
  ## * ``cb`` - Pull stats once then disconnect. Corresponding to ``stream`` of docker
  ##   remote api, handle response in streaming. 
  ##
  ## Example stat:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##    "read" : "2015-01-08T22:57:31.547920715Z",
  ##    "networks": {
  ##      "eth0": {
  ##        "rx_bytes": 5338,
  ##        "rx_dropped": 0,
  ##        "rx_errors": 0,
  ##        "rx_packets": 36,
  ##        "tx_bytes": 648,
  ##        "tx_dropped": 0,
  ##        "tx_errors": 0,
  ##        "tx_packets": 8
  ##      },
  ##      "eth5": {
  ##        "rx_bytes": 4641,
  ##        "rx_dropped": 0,
  ##        "rx_errors": 0,
  ##        "rx_packets": 26,
  ##        "tx_bytes": 690,
  ##        "tx_dropped": 0,
  ##        "tx_errors": 0,
  ##        "tx_packets": 9
  ##      }
  ##    },
  ##    "memory_stats" : {
  ##      "stats" : {
  ##        "total_pgmajfault" : 0,
  ##        "cache" : 0,
  ##        "mapped_file" : 0,
  ##        "total_inactive_file" : 0,
  ##        "pgpgout" : 414,
  ##        "rss" : 6537216,
  ##        "total_mapped_file" : 0,
  ##        "writeback" : 0,
  ##        "unevictable" : 0,
  ##        "pgpgin" : 477,
  ##        "total_unevictable" : 0,
  ##        "pgmajfault" : 0,
  ##        "total_rss" : 6537216,
  ##        "total_rss_huge" : 6291456,
  ##        "total_writeback" : 0,
  ##        "total_inactive_anon" : 0,
  ##        "rss_huge" : 6291456,
  ##        "hierarchical_memory_limit" : "67108864", 
  ##        "total_pgfault" : 964,
  ##        "total_active_file" : 0,
  ##        "active_anon" : 6537216,
  ##        "total_active_anon" : 6537216,
  ##        "total_pgpgout" : 414,
  ##        "total_cache" : 0,
  ##        "inactive_anon" : 0,
  ##        "active_file" : 0,
  ##        "pgfault" : 964,
  ##        "inactive_file" : 0,
  ##        "total_pgpgin" : 477
  ##      },
  ##      "max_usage" : 6651904,
  ##      "usage" : 6537216,
  ##      "failcnt" : 0,
  ##      "limit" : 67108864
  ##    },
  ##    "blkio_stats" : {},
  ##    "cpu_stats" : {
  ##      "cpu_usage" : {
  ##        "percpu_usage" : [
  ##          16970827,
  ##          1839451,
  ##          7107380,
  ##          10571290
  ##        ],
  ##        "usage_in_usermode" : 10000000,
  ##        "total_usage" : 36488948,
  ##        "usage_in_kernelmode" : 20000000
  ##      },
  ##      "system_cpu_usage" : 20091722000000000,
  ##      "throttling_data" : {}
  ##    }
  ##   } 
  proc callback(chunk: string): bool = 
    try:
      # There's an error `out of valid range` of `hierarchical_memory_limit`.
      let data = replace(chunk, re("\"hierarchical_memory_limit\":(\\d+)"), 
                                   "\"hierarchical_memory_limit\":\"$1\"")
      result = cb(parseJson(data))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())

  var queries: seq[string] = @[]
  if stream:
    add(queries, "stream", "1") 
  else:
    add(queries, "stream", "0") 
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/stats", queries)
  let res =
    if stream: 
      await request(c, httpGET, url, cb = if cb == nil: nil else: callback)
    else:
      await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    if not stream:
      discard callback(res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc resize*(c: AsyncDocker, name: string, width: int, height: int)  {.async.} =
  ## Resize the TTY for container with `name` (name or id). The unit is number of characters. 
  ## You must restart the container for the resize to take effect. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#resize-a-container-tty>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``width`` - New Width of `tty` session.
  ## * ``height`` - New height of `tty` session.
  var queries: seq[string] = @[]
  add(queries, "w", $width)
  add(queries, "h", $height)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/resize", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc start*(c: AsyncDocker, name: string, detachKeys: string = nil) {.async.} =
  ## Start the container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#start-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id. 
  ## * ``detachKeys`` - Override the key sequence for detaching a container. Format is 
  ##   a single character ``[a-Z]`` or ``ctrl-<value>`` where ``<value>`` is one of:
  ##   ``a-z`` ``@`` ``^`` ``[`` ``,`` ``_``.
  var queries: seq[string] = @[]
  if detachKeys != nil:
    add(queries, "detachKeys", detachKeys)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/start")
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204, 304:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc stop*(c: AsyncDocker, name: string, time = 10) {.async.} =
  ## Stop the container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#stop-a-container>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters: 
  ##
  ## * ``name`` - The container name or id. 
  ## * ``time`` - Number of seconds to wait before killing the container.
  var queries: seq[string] = @[]
  add(queries, "t", $time)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/stop", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204, 304:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc restart*(c: AsyncDocker, name: string, time = 10) {.async.} =
  ## Restart the container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#restart-a-container>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters: 
  ##
  ## * ``name`` - The container name or id. 
  ## * ``time`` - Number of seconds to wait before killing the container.
  ## Restart the container `name`.
  var queries: seq[string] = @[]
  add(queries, "t", $time)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/restart", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc kill*(c: AsyncDocker, name: string, signal = "SIGKILL") {.async.} =
  ## Kill the container `name` (name or id). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#kill-a-container>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or ``DockerError``.   
  ##
  ## Request parameters: 
  ##
  ## * ``name`` - The container name or id. 
  ## * ``signal`` - Signal to send to the container: integer or string like
  ##   SIGINT. When not set, SIGKILL is assumed and the call waits for the 
  ##   container to exit.
  var queries: seq[string] = @[]
  add(queries, "signal", signal)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/kill", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc update*(c: AsyncDocker; name: string; 
             blkioWeight, cpuShares, cpuPeriod, cpuQuota = 0;
             cpusetCpus, cpusetMems = "";
             memory, memorySwap, memoryReservation, kernelMemory = 0): Future[JsonNode] {.async.} =
  ## Update resource configs of one or more containers. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#update-a-container>`_
  ##
  ## `FutureError`` represents an exception, it may be ``BadParameterError``, ``NotFoundError``, 
  ## ``ServerError`` or `DockerError`.  
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. 
  ## For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Warnings": []
  ##   }
  var jBody = newJObject()
  if blkioWeight > 0:
    add(jBody, "BlkioWeight", %blkioWeight)
  if cpuShares > 0:
    add(jBody, "CpuShares", %cpuShares)
  if cpuPeriod > 0:
    add(jBody, "CpuPeriod", %cpuPeriod)
  if cpuQuota > 0:
    add(jBody, "CpuQuota", %cpuQuota)
  if cpusetCpus != nil and cpusetCpus != "":
    add(jBody, "CpusetCpus", %cpusetCpus)
  if cpusetMems != nil and cpusetMems != "":
    add(jBody, "CpusetMems", %cpusetMems)
  if memory > 0:
    add(jBody, "Memory", %memory)
  if memorySwap > 0:
    add(jBody, "MemorySwap", %memorySwap)
  if memoryReservation > 0:
    add(jBody, "MemoryReservation", %memoryReservation)
  if kernelMemory > 0:
    add(jBody, "KernelMemory", %kernelMemory)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/update")
  var headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 200:
    try:
        result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc rename*(c: AsyncDocker, name: string, newname: string) {.async.} =
  ## Rename the container `name` to `newname`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#rename-a-container>`_
  ##
  ## `FutureError`` represents an exception, it may be ``NotFoundError``, ``ConflictError``, 
  ## ``ServerError`` or `DockerError`.  
  ##
  ## ## Request parameters: 
  ##
  ## * ``name`` - The container name or id. 
  ## * ``newname`` - The container new name or id.
  var queries: seq[string] = @[]
  add(queries, "name", newname)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/rename", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc pause*(c: AsyncDocker, name: string) {.async.} =
  ## Pause the container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#pause-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id. 
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/pause")
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc unpause*(c: AsyncDocker, name: string) {.async.} =
  ## Unpause the container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#unpause-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id. 
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/unpause")
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc attach*(c: AsyncDocker; name: string; detachKeys: string = nil;
             logs, stream, stdin, stdout, stderr = false;
             cb: proc(stream: int, data: string): bool) {.async.} =
  ## Attach to the container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#attach-to-a-container>`_ 
  ##
  ## ``FutureError`` represents an exception, it may be `BadParameterError`, 
  ## ``NotFoundError``, ``ServerError`` or `DockerError`.   
  ## 
  ## REquest parameters:
  ##
  ## * ``name`` - The container name or id. 
  ## * ``logs`` - Return logs.
  ## * ``stream`` - Return stream. 
  ## * ``stdin`` - If `stream=true`, attach to stdin.
  ## * ``stdout`` - If `logs=true`, return `stdout` log, if `stream=true`, attach to `stdout`.
  ## * ``stderr`` - If `logs=true`, return `stderr` log, if `stream=true`, attach to `stderr`.
  ## * ``cb`` - Handles the data from docker daemon.
  var queries: seq[string] = @[]
  if detachKeys != nil and detachKeys != "":
    add(queries, "detachKeys", detachKeys)
  if logs:
    add(queries, "logs", "1")
  if stream:
    add(queries, "stream", "1")
  if stdin:
    add(queries, "stdin", "1")
  if stdout:
    add(queries, "stdout", "1")
  if stderr:
    add(queries, "stderr", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/attach", queries)
  let res = await request(c, httpPOST, url, 
                          cb = if cb == nil: nil else: parseVnd(cb))
  case res.statusCode:
  of 101, 200:
    discard
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)
 
proc wait*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Waiting for container `name` stops, then returns the exit code. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#wait-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine.
  ## For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {"StatusCode": 0}
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/wait")
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc rm*(c: AsyncDocker, name: string, volumes = false, force = false) {.async.} =
  ## Remove the container `name` from the filesystem. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#remove-a-container>`_
  ##
  ## ``FutureError`` represents an exception, it may be `BadParameterError`, 
  ## ``NotFoundError``, ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id. 
  ## * ``volumes`` - Remove the volumes associated to the container.
  ## * ``force`` - Kill then remove the container.
  var queries: seq[string] = @[]
  if volumes:
    add(queries, "v", "1")
  if force:
    add(queries, "force", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name, queries)
  let res = await request(c, httpDELETE, url)
  case res.statusCode:
  of 204:
    discard
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc retrieveArchive*(c: AsyncDocker, name: string, path: string): Future[JsonNode] {.async.} =  
  ## Retrieving information about files and folders in the container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#retrieving-information-about-files-and-folders-in-a-container`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``BadParameterError``, 
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``path`` - Resource in the container’s filesystem to archive. 
  ##   
  ##   If not an absolute path, it is relative to the container’s root directory. The 
  ##   resource specified by ``path`` must exist. To assert that the resource is expected 
  ##   to be a directory, ``path`` should end in / or /. (assuming a path separator of /). 
  ##   If path ends in /. then this indicates that only the contents of the path directory 
  ##   should be copied. A symlink is always resolved to its target.   
  ##
  ##   Note: It is not possible to copy certain system files such as resources under `/proc`, 
  ##   `/sys`, `/dev`, and mounts created by the user in the container.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ## 
  ##   {
  ##     "name": "home",
  ##     "size": 4096,
  ##     "mode": 2147484141,
  ##     "mtime": "2014-04-11T06:12:14+08:00",
  ##     "linkTarget": ""
  ##   }
  var queries: seq[string] = @[]
  add(queries, "path", path)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/archive", queries)
  let res = await request(c, httpHEAD, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(decode(res.headers["X-Docker-Container-Path-Stat"]))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc getArchive*(c: AsyncDocker, name: string, path: string,
                 cb: proc(archive: string): bool): Future[JsonNode] {.async.} =  
  ## Get an tar archive of a resource in the filesystem of container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-an-archive-of-a-filesystem-resource-in-a-container`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``BadParameterError``, 
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``path`` - Resource in the container’s filesystem to archive.
  ## * ``cb`` - Handles the archives from docker daemon.
  ##  
  ##   If not an absolute path, it is relative to the container’s root directory. The 
  ##   resource specified by ``path`` must exist. To assert that the resource is expected 
  ##   to be a directory, ``path`` should end in / or /. (assuming a path separator of /). 
  ##   If path ends in /. then this indicates that only the contents of the path directory 
  ##   should be copied. A symlink is always resolved to its target.   
  ##
  ##   Note: It is not possible to copy certain system files such as resources under `/proc`, 
  ##   `/sys`, `/dev`, and mounts created by the user in the container.
  ##
  ## * ``noOverwriteDirNonDir`` - If `true` then it will be an error if unpacking the
  ##    given content would cause an existing directory to be replaced with a 
  ##    non-directory and vice versa.
  ## * ``cb`` - Handles the tar archive from docker daemon.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ## 
  ##   {
  ##     "name": "home",
  ##     "size": 4096,
  ##     "mode": 2147484141,
  ##     "mtime": "2014-04-11T06:12:14+08:00",
  ##     "linkTarget": ""
  ##   }
  var queries: seq[string] = @[]
  add(queries, "path", path)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/archive", queries)
  let res = await request(c, httpGET, url, cb = cb)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(decode(res.headers["X-Docker-Container-Path-Stat"]))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc putArchive*(c: AsyncDocker, name: string, path: string, archive: string,
                 noOverwriteDirNonDir = false) {.async.} =  
  ## Upload a tar archive to be extracted to a path in the filesystem of container `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#extract-an-archive-of-files-or-folders-to-a-directory-in-a-container`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``BadParameterError``, 
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The container name or id.
  ## * ``path`` - Resource in the container’s filesystem to archive. 
  ##   
  ##   If not an absolute path, it is relative to the container’s root directory. The 
  ##   resource specified by ``path`` must exist. To assert that the resource is expected 
  ##   to be a directory, ``path`` should end in / or /. (assuming a path separator of /). 
  ##   If path ends in /. then this indicates that only the contents of the path directory 
  ##   should be copied. A symlink is always resolved to its target.   
  ##
  ##   Note: It is not possible to copy certain system files such as resources under `/proc`, 
  ##   `/sys`, `/dev`, and mounts created by the user in the container.
  ##
  ## * ``noOverwriteDirNonDir`` - If `true` then it will be an error if unpacking the
  ##    given content would cause an existing directory to be replaced with a 
  ##    non-directory and vice versa.
  ## * ``archive`` - The tar archive.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ## 
  ##   {
  ##     "name": "home",
  ##     "size": 4096,
  ##     "mode": 2147484141,
  ##     "mtime": "2014-04-11T06:12:14+08:00",
  ##     "linkTarget": ""
  ##   }
  var queries: seq[string] = @[]
  add(queries, "path", path)
  if noOverwriteDirNonDir:
    add(queries, "noOverwriteDirNonDir", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/archive", queries)
  let headers = newStringTable({"Content-Type":"application/x-tar"})
  let res = await request(c, httpPUT, url, headers, archive)
  case res.statusCode:
  of 200:
    discard
  of 400:
    raise newException(BadParameterError, res.body)
  of 403:
    raise newException(ForbiddenError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc images*(c: AsyncDocker; all, digests = false; 
             danglingFilters = false; labelFilters: seq[string] = nil;
             filter: string = nil): Future[JsonNode] {.async.} =
  ## List Images. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#list-images>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``DockerError``. 
  ##
  ## Request parameters:
  ## 
  ## * ``all`` - Show all images. 
  ## * ``danglingFilters``, ``labelFilters`` - Filters to process on the images list. Available filters: 
  ##   * `dangling=true`
  ##   * `label=key` or `label="key=value"` of an image label
  ## * ``filter`` - Only return images with the specified name.
  ##
  ##   For swarm api, use `--filter node=<Node name>` to show images
  ##   of the specific node.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##
  ##   [
  ##     {
  ##        "RepoTags": [
  ##          "ubuntu:12.04",
  ##          "ubuntu:precise",
  ##          "ubuntu:latest"
  ##        ],
  ##        "Id": "8dbd9e392a964056420e5d58ca5cc376ef18e2de93b5cc90e868a1bbc8318c1c",
  ##        "Created": 1365714795,
  ##        "Size": 131506275,
  ##        "VirtualSize": 131506275,
  ##        "Labels": {}
  ##     },
  ##     {
  ##        "RepoTags": [
  ##          "ubuntu:12.10",
  ##          "ubuntu:quantal"
  ##        ],
  ##        "ParentId": "27cf784147099545",
  ##        "Id": "b750fe79269d2ec9a3c593ef05b4332b1d1a02a62b4accb2c21d589ff2f5f2dc",
  ##        "Created": 1364102658,
  ##        "Size": 24653,
  ##        "VirtualSize": 180116135,
  ##        "Labels": {
  ##           "com.example.version": "v1"
  ##        }
  ##     }
  ##   ]
  var queries: seq[string] = @[]
  if all:
    add(queries, "all", "1")
  if digests:
    add(queries, "digests", "1")
  var JFilters = newJObject()
  if danglingFilters:
    add(JFilters, "dangling", newJArray())
    add(JFilters["dangling"], %($danglingFilters))
  if labelFilters != nil:
    add(JFilters, "label", newJArray())
    for i in labelFilters:
      add(JFilters["label"], %i)
  add(queries, "filters", $JFilters)
  if filter != nil and filter != "":
    add(queries, "filter", filter)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/json", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  else:
    raise newException(DockerError, res.body)

proc build*(c: AsyncDocker; tarball: string;
            dockerfile, t, remote: string = nil; 
            q, nocache, pull, forcerm = false; rm = true;
            memory = 0; memswap = -1; cpushares, cpusetcpus: string = nil;
            cpuperiod, cpuquota, shmsize = 0; 
            buildargs: seq[tuple[key: string, value: string]] = nil; 
            registryAuth: seq[tuple[url, username, password: string]] = nil;
            cb: proc(state: JsonNode): bool = nil) {.async.} =
  ## Build an image from a Dockerfile. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#build-image-from-a-dockerfile>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` or ``DockerError``.
  ##
  ## Request parameters:
  ##
  ## * ``tarball`` - The input stream must be a tar archive compressed with one of the 
  ##   following algorithms: identity (no compression), gzip, bzip2, xz.
  ## * ``dockerfile`` - Path within the build context to the Dockerfile. This is ignored if 
  ##   ``remote`` is specified and points to an individual filename.
  ## * ``t`` - A name and optional tag to apply to the image in the `name:tag` format. If you
  ##   omit the `tag` the default `latest` value is assumed. You can provide one or more t parameters. 
  ## * ``remote`` - A Git repository URI or HTTP/HTTPS URI build source. If the URI specifies
  ##   a filename, the file’s contents are placed into a file called `Dockerfile`.
  ## * ``q`` - Suppress verbose build output.
  ## * ``nocache`` - Do not use the cache when building the image.
  ## * ``pull`` - Attempt to pull the image even if an older image exists locally.
  ## * ``rm`` - Remove intermediate containers after a successful build (default behavior).
  ## * ``forcerm`` - Always remove intermediate containers (includes ``rm``).
  ## * ``memory`` - Set memory limit for build.
  ## * ``memswap`` - Total memory (memory + swap), `-1` to enable unlimited swap. 
  ## * ``cpushares`` - CPU shares (relative weight).
  ## * ``cpusetcpus`` - CPUs in which to allow execution (e.g., `0-3`, `0,1`).
  ## * ``cpuperiod`` - The length of a CPU period in microseconds.
  ## * ``cpuquota`` - Microseconds of CPU time that the container can get in a CPU period.
  ## * ``buildargs`` - JSON map of string pairs for build-time variables. Users pass these values at
  ##   build-time. Docker uses the buildargs as the environment context for command(s) run via the
  ##   Dockerfile’s RUN instruction or for variable expansion in other Dockerfile instructions. This
  ##   is not meant for passing secret values.
  ## * ``shmsize`` - Size of /dev/shm in bytes. The size must be greater than 0. If omitted the system
  ##   uses 64MB.
  ## * ``registry`` - Registry auth config. 
  proc callback(chunk: string): bool = 
    try:
      result = cb(parseJson(chunk))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())

  var queries: seq[string] = @[]
  if dockerfile != nil and dockerfile != "":
    add(queries, "dockerfile", dockerfile)
  if remote != nil and remote != "":
    add(queries, "remote", remote)
  if t != nil and t != "":
    add(queries, "t", t)
  if q:
    add(queries, "q", "1")
  if nocache:
    add(queries, "nocache", "1")
  if pull:
    add(queries, "pull", "1")
  if rm:
    add(queries, "rm", "1")
  if forcerm:
    add(queries, "forcerm", "1")
  if memory > 0:
    add(queries, "memory", $memory)
  if memswap > 0:
    add(queries, "memswap", $memswap)
  if cpushares != nil and cpushares != "":
    add(queries, "cpushares", cpushares)
  if cpusetcpus != nil and cpusetcpus != "":
    add(queries, "cpusetcpus", cpusetcpus)
  if cpuperiod > 0:
    add(queries, "cpuperiod", $cpuperiod)
  if cpuquota > 0:
    add(queries, "cpuquota", $cpuquota)
  if shmsize > 0:
    add(queries, "shmsize", $shmsize)
  if buildargs != nil:
    var jBuildargs = newJObject()
    for i in buildargs:
      add(jBuildargs, i.key, %i.value)
    add(queries, "buildargs", $jBuildargs)
  var JRegistryAuth = newJObject()
  if registryAuth != nil:
    for i in registryAuth:
      add(JRegistryAuth, i.url, newJObject())
      add(JRegistryAuth["i.url"], "username", %i.username)
      add(JRegistryAuth["i.url"], "password", %i.password)
  let headers = newStringTable({"Content-type": "application/tar", 
                                "X-Registry-Config": encode($JRegistryAuth)})
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/build", queries)
  let res = await request(c, httpPOST, url, headers, tarball, 
                          if cb == nil: nil else: callback)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc pull*(c: AsyncDocker; fromImage: string; 
           fromSrc, repo, tag: string = nil;
           registryAuth: tuple[username, password, email: string] = (nil, nil, nil);
           cb: proc(state: JsonNode): bool) {.async.} =
  ## Create an image either by pulling it from the registry or by importing it. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#create-an-image>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError``
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``fromImage`` - Name of the image to pull. The name may include a tag or digest. This parameter
  ##   may only be used when pulling an image. The pull is cancelled if  the HTTP connection is closed.
  ## * ``fromSrc`` - Source to import. The value may be a URL from which the image can be retrieved or
  ##   ``-`` to read the image from the request body. This parameter may only be used when importing an image.
  ## * ``repo`` - Repository name given to an image when it is imported. The repo may include a tag. This 
  ##   parameter may only be used when importing an image.
  ## * ``tag`` - Tag or digest.
  ## * ``registry`` - Registry auth config.
  ## * ``cb`` - Handle the response state.
  proc callback(chunk: string): bool = 
    try:
      result = cb(parseJson(chunk))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())

  var queries: seq[string] = @[]
  add(queries, "fromImage", fromImage)
  if fromSrc != nil:
    add(queries, "fromSrc", fromSrc)
  if repo != nil:
    add(queries, "repo", repo)
  if tag != nil:
    add(queries, "tag", tag)
  var JRegistryAuth = newJObject()
  add(JRegistryAuth, "username", %registryAuth.username)
  add(JRegistryAuth, "password", %registryAuth.password)
  add(JRegistryAuth, "email", %registryAuth.email)
  add(queries, "X-Registry-Auth", encode($JRegistryAuth))
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/create", queries)
  let res = await request(c, httpPOST, url, 
                          cb = if cb == nil: nil else: callback)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc inspectImage*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Return low-level information on the image `name`. see `Docker Reference<https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-an-image>`_
  ##
  ## ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The image name or id.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##    "Id" : "85f05633ddc1c50679be2b16a0479ab6f7637f8884e0cfe0f4d20e1ebb3d6e7c",
  ##    "Container" : "cb91e48a60d01f1e27028b4fc6819f4f290b3cf12496c8176ec714d0d390984a",
  ##    "Comment" : "",
  ##    "Os" : "linux",
  ##    "Architecture" : "amd64",
  ##    "Parent" : "91e54dfb11794fad694460162bf0cb0a4fa710cfa3f60979c177d920813e267c",
  ##    "ContainerConfig" : {
  ##      "Tty" : false,
  ##      "Hostname" : "e611e15f9c9d",
  ##      "Volumes" : null,
  ##      "Domainname" : "",
  ##      "AttachStdout" : false,
  ##      "PublishService" : "",
  ##      "AttachStdin" : false,
  ##      "OpenStdin" : false,
  ##      "StdinOnce" : false,
  ##      "NetworkDisabled" : false,
  ##      "OnBuild" : [],
  ##      "Image" : "91e54dfb11794fad694460162bf0cb0a4fa710cfa3f60979c177d920813e267c",
  ##      "User" : "",
  ##      "WorkingDir" : "",
  ##      "Entrypoint" : null,
  ##      "MacAddress" : "",
  ##      "AttachStderr" : false,
  ##      "Labels" : {
  ##        "com.example.license" : "GPL",
  ##        "com.example.version" : "1.0",
  ##        "com.example.vendor" : "Acme"
  ##      },
  ##      "Env" : [
  ##        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  ##      ],
  ##      "ExposedPorts" : null,
  ##      "Cmd" : [
  ##        "/bin/sh",
  ##        "-c",
  ##        "##  (nop) LABEL com.example.vendor=Acme com.example.license=GPL com.example.version=1.0"
  ##      ]
  ##    },
  ##    "DockerVersion" : "1.9.0-dev",
  ##    "VirtualSize" : 188359297,
  ##    "Size" : 0,
  ##    "Author" : "",
  ##    "Created" : "2015-09-10T08:30:53.26995814Z",
  ##    "GraphDriver" : {
  ##      "Name" : "aufs",
  ##      "Data" : null
  ##    },
  ##    "RepoDigests" : [
  ##      "localhost:5000/test/busybox/example@sha256:cbbf2f9a99b47fc460d422812b6a5adff7dfee951d8fa2e4a98caa0382cfbdbf"
  ##    ],
  ##    "RepoTags" : [
  ##      "example:1.0",
  ##      "example:latest",
  ##      "example:stable"
  ##    ],
  ##    "Config" : {
  ##      "Image" : "91e54dfb11794fad694460162bf0cb0a4fa710cfa3f60979c177d920813e267c",
  ##      "NetworkDisabled" : false,
  ##      "OnBuild" : [],
  ##      "StdinOnce" : false,
  ##      "PublishService" : "",
  ##      "AttachStdin" : false,
  ##      "OpenStdin" : false,
  ##      "Domainname" : "",
  ##      "AttachStdout" : false,
  ##      "Tty" : false,
  ##      "Hostname" : "e611e15f9c9d",
  ##      "Volumes" : null,
  ##      "Cmd" : [
  ##        "/bin/bash"
  ##      ],
  ##      "ExposedPorts" : null,
  ##      "Env" : [
  ##        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  ##      ],
  ##      "Labels" : {
  ##        "com.example.vendor" : "Acme",
  ##        "com.example.version" : "1.0",
  ##        "com.example.license" : "GPL"
  ##      },
  ##      "Entrypoint" : null,
  ##      "MacAddress" : "",
  ##      "AttachStderr" : false,
  ##      "WorkingDir" : "",
  ##      "User" : ""
  ##    }
  ##   }
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/" & name & "/json")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc history*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Return the history of the image `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-the-history-of-an-image>`_
  ##    
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` 
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The image name or id.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   [
  ##     {
  ##       "Id": "3db9c44f45209632d6050b35958829c3a2aa256d81b9a7be45b362ff85c54710",
  ##       "Created": 1398108230,
  ##       "CreatedBy": "/bin/sh -c ##  (nop) ADD file:eb15dbd63394e063b805a3c32ca7bf0266ef64676d5a6fab4801f2e81e2a5148 in /",
  ##       "Tags": [
  ##         "ubuntu:lucid",
  ##         "ubuntu:10.04"
  ##       ],
  ##       "Size": 182964289,
  ##       "Comment": ""
  ##     },
  ##     {
  ##       "Id": "6cfa4d1f33fb861d4d114f43b25abd0ac737509268065cdfd69d544a59c85ab8",
  ##       "Created": 1398108222,
  ##       "CreatedBy": "/bin/sh -c ##  (nop) MAINTAINER Tianon Gravi <admwiggin@gmail.com> - mkimage-debootstrap.sh -i iproute,iputils-ping,ubuntu-minimal -t lucid.tar.xz lucid http://archive.ubuntu.com/ubuntu/",
  ##       "Tags": null,
  ##       "Size": 0,
  ##       "Comment": ""
  ##     },
  ##     {
  ##       "Id": "511136ea3c5a64f264b78b5433614aec563103b4d4702f3ba7d4d2698e22c158",
  ##       "Created": 1371157430,
  ##       "CreatedBy": "",
  ##       "Tags": [
  ##         "scratch12:latest",
  ##         "scratch:latest"
  ##       ],
  ##       "Size": 0,
  ##       "Comment": "Imported from -"
  ##     }
  ##   ]
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/" & name & "/history")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc push*(c: AsyncDocker, name: string, tag: string = nil,
           registryAuth: tuple[username, password, email: string] = (nil, nil, nil),
           cb: proc(state: JsonNode): bool) {.async.} =
  ## Push the image `name` on the registry. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#push-an-image-on-the-registry>`_
  ##
  ## If you wish to push an image on to a private registry, that image must already
  ## have a tag into a repository which references that registry hostname and port.
  ## This repository name should then be used in the URL. This duplicates the command
  ## line’s flow.
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## ``ServerError`` or `DockerError`.   
  ## 
  ## Request parameters:
  ##
  ## * ``name`` - The image name or id.
  ## * ``tag`` - Show the containers sizes.
  ## * ``registryAuth`` - Login information.
  ## * ``cb`` - Handle the response state. State example:
  ##
  ##   .. code-block:: nim
  ##
  ##     {"status": "Pushing..."}
  ##     {"status": "Pushing", "progress": "1/? (n/a)", "progressDetail": {"current": 1}}}
  ##     {"error": "Invalid..."}
  ##     ...
  proc callback(chunk: string): bool = 
    try:
      result = cb(parseJson(chunk))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())

  var queries: seq[string] = @[]
  if tag != nil:
    add(queries, "tag", tag)
  var JRegistryAuth = newJObject() 
  if registryAuth.username != nil:
    add(JRegistryAuth, "username", %registryAuth.username)
    add(JRegistryAuth, "password", %registryAuth.password)
    add(JRegistryAuth, "email", %registryAuth.email)
  let headers = newStringTable({"X-Registry-Auth": encode($JRegistryAuth)})
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/" & name & "/push", queries)
  let res = await request(c, httpPOST, url, headers, 
                          cb = if cb == nil: nil else: callback)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc tag*(c: AsyncDocker; name, repo, tag: string; force = false) {.async.} =
  ## Tag the image `name` into a repository. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#tag-an-image-into-a-repository>`_
  ##
  ## ``FutureError`` represents an exception, it may be `BadParameterError`, 
  ## ``NotFoundError``, ``ServerError``, `ConflictError`or `DockerError`.   
  ## 
  ## Request parameters:
  ##
  ## * ``name`` - The image name or id.
  ## * ``tag`` - The new tag name.
  ## * ``force`` - .
  var queries: seq[string] = @[]
  add(queries, "repo", repo)
  add(queries, "tag", tag)
  if force:
    add(queries, "force", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/" & name & "/tag", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 201:
    discard
  of 400:
    raise newException(BadParameterError, res.body)
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc rmImage*(c: AsyncDocker, name: string,
              force, noprune = false): Future[JsonNode] {.async.} =
  ## Remove the image `name` from the filesystem. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#remove-an-image>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, 
  ## `ConflictError`, ``ServerError`` or `DockerError`. 
  ## 
  ## Request paramters:
  ##
  ## * ``name`` - The image name or id.
  ## * ``force`` - Force removal of the image.
  ## * ``noprune`` - Do not delete untagged parents.
  ##  
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ## 
  ##   [
  ##     {"Untagged": "3e2f21a89f"},
  ##     {"Deleted": "3e2f21a89f"},
  ##     {"Deleted": "53b4f83ac9"}
  ##   ]
  var queries: seq[string] = @[]
  if force:
    add(queries, "force", "1")
  if noprune:
    add(queries, "noprune", "1")
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/" & name, queries)
  let res = await request(c, httpDELETE, url)
  case res.statusCode:
  of 200:
    try:
      result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc search*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Search for an image on Docker Hub. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#search-images>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError``, 
  ## or `DockerError`.    
  ## 
  ## Request parameters:
  ##
  ## * ``name`` - The term to search.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ## 
  ##   [
  ##     {
  ##       "description": "",
  ##       "is_official": false,
  ##       "is_automated": false,
  ##       "name": "wma55/u1210sshd",
  ##       "star_count": 0
  ##     },
  ##     {
  ##       "description": "",
  ##       "is_official": false,
  ##       "is_automated": false,
  ##       "name": "jdswinbank/sshd",
  ##       "star_count": 0
  ##     },
  ##     {
  ##       "description": "",
  ##       "is_official": false,
  ##       "is_automated": false,
  ##       "name": "vgauthier/sshd",
  ##       "star_count": 0
  ##     }
  ##   ...
  ##   ]
  var queries: seq[string] = @[]
  add(queries, "term", name)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/images/search", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc auth*(c: AsyncDocker; username, password: string;
           email, serveraddress: string): Future[JsonNode] {.async.} =
  ## Check auth configuration. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#check-auth-configuration>`_
  ## 
  ## ``FutureError`` represents an exception, it may be ``ServerError``, 
  ## or `DockerError`.
  let body = %*{
    "username": username,
    "password": password,
    "email": email,
    "serveraddress": serveraddress
  }
  let url = parseUri(c.scheme, c.hostname, c.port, "/auth")
  let headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $body)
  case res.statusCode:
  of 200, 204:
    try:
      result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc info*(c: AsyncDocker): Future[JsonNode] {.async.} =
  ## Display system-wide information. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#display-system-wide-information>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` or `DockerError`.  
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##    "Containers": 11,
  ##    "CpuCfsPeriod": true,
  ##    "CpuCfsQuota": true,
  ##    "Debug": false,
  ##    "DiscoveryBackend": "etcd://localhost:2379",
  ##    "DockerRootDir": "/var/lib/docker",
  ##    "Driver": "btrfs",
  ##    "DriverStatus": [[""]],
  ##    "ExecutionDriver": "native-0.1",
  ##    "ExperimentalBuild": false,
  ##    "HttpProxy": "http://test:test@localhost:8080",
  ##    "HttpsProxy": "https://test:test@localhost:8080",
  ##    "ID": "7TRN:IPZB:QYBB:VPBQ:UMPP:KARE:6ZNR:XE6T:7EWV:PKF4:ZOJD:TPYS",
  ##    "IPv4Forwarding": true,
  ##    "Images": 16,
  ##    "IndexServerAddress": "https://index.docker.io/v1/",
  ##    "InitPath": "/usr/bin/docker",
  ##    "InitSha1": "",
  ##    "KernelVersion": "3.12.0-1-amd64",
  ##    "Labels": [
  ##      "storage=ssd"
  ##    ],
  ##    "MemTotal": 2099236864,
  ##    "MemoryLimit": true,
  ##    "NCPU": 1,
  ##    "NEventsListener": 0,
  ##    "NFd": 11,
  ##    "NGoroutines": 21,
  ##    "Name": "prod-server-42",
  ##    "NoProxy": "9.81.1.160",
  ##    "OomKillDisable": true,
  ##    "OperatingSystem": "Boot2Docker",
  ##    "RegistryConfig": {
  ##      "IndexConfigs": {
  ##        "docker.io": {
  ##          "Mirrors": null,
  ##          "Name": "docker.io",
  ##          "Official": true,
  ##          "Secure": true
  ##        }
  ##      },
  ##      "InsecureRegistryCIDRs": [
  ##        "127.0.0.0/8"
  ##      ]
  ##    },
  ##    "SwapLimit": false,
  ##    "SystemTime": "2015-03-10T11:11:23.730591467-07:00"
  ##    "ServerVersion": "1.9.0"
  ##   }  
  let url = parseUri(c.scheme, c.hostname, c.port, "/info")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc version*(c: AsyncDocker): Future[JsonNode] {.async.} =
  ## Display system-wide information. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#show-the-docker-version-information>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` or `DockerError`.  
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##    "Version": "1.5.0",
  ##    "Os": "linux",
  ##    "KernelVersion": "3.18.5-tinycore64",
  ##    "GoVersion": "go1.4.1",
  ##    "GitCommit": "a8a31ef",
  ##    "Arch": "amd64",
  ##    "ApiVersion": "1.20",
  ##    "Experimental": false
  ##   }
  let url = parseUri(c.scheme, c.hostname, c.port, "/version")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc ping*(c: AsyncDocker): Future[string] {.async.} =
  ## Ping the docker server. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#ping-the-docker-server>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` or `DockerError`.  
  ##
  ## Result is a string. For example: 
  ##
  ## .. code-block:: nim
  ##
  ##   OK
  let url = parseUri(c.scheme, c.hostname, c.port, "/_ping")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    return res.body
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc commit*(c: AsyncDocker; container: string; 
             repo, tag: string; 
             comment, author = ""; 
             pause = false; changes = "";
             hostname, domainname, user = "";
             attachStdin, attachStdout, attachStderr, tty = false;
             openStdin, stdinOnce = false;
             env, cmd, volumes, exposedPorts: seq[string] = nil;
             labels: seq[tuple[key, value: string]] = nil;
             workingDir = "";
             networkDisabled = false): Future[JsonNode] {.async.} =
  ## Create a new image from a container’s changes. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#create-a-new-image-from-a-container-s-changes>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``container`` - Source container.
  ## * ``repo`` - Repository.
  ## * ``tag`` - Tag.
  ## * ``comment`` - Commit message.
  ## * ``author`` - Author (e.g., `John Hannibal Smith <hannibal@a-team.com>`).
  ## * ``pause`` - Whether to pause the container before committing.
  ## * ``changes`` - Dockerfile instructions to apply while committing.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ##
  ##   {"Id": "596069db4bf5"}
  var queries: seq[string] = @[]
  add(queries, "container", container)
  if repo != nil and repo != "":
    add(queries, "repo", repo)
  if tag != nil and tag != "":
    add(queries, "tag", tag)
  if comment != nil and comment != "":
    add(queries, "comment", comment)
  if author != nil and author != "":
    add(queries, "author", author)
  if pause:
    add(queries, "pause", "1")
  if changes != nil and changes != "":
    add(queries, "changes", changes)
  var jBody = newJObject()
  add(jBody, "Hostname", %hostname)
  add(jBody, "Domainname", %domainname)
  add(jBody, "User", %user)
  add(jBody, "AttachStdin", %attachStdin)
  add(jBody, "AttachStdout", %attachStdout)
  add(jBody, "AttachStderr", %attachStderr)
  add(jBody, "Tty", %tty)
  add(jBody, "OpenStdin", %openStdin)
  add(jBody, "StdinOnce", %stdinOnce)
  add(jBody, "Env", env)
  add(jBody, "Cmd", cmd)
  add(jBody, "Labels", labels)
  add(jBody, "WorkingDir", %workingDir)
  add(jBody, "NetworkDisabled", %networkDisabled)
  var jExposedPorts = newJObject()
  for i in exposedPorts:
    add(jExposedPorts, i, newJObject())
  add(jBody, "ExposedPorts", jExposedPorts)
  var jVolumes = newJObject()
  for i in volumes:
    add(jVolumes, i, newJObject())
  add(jBody, "Volumes", jVolumes)
  let url = parseUri(c.scheme, c.hostname, c.port, "/commit", queries)
  let headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 201:
    try:
      result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)
  
proc events*(c: AsyncDocker; since, until = 0; 
             filters: seq[tuple[key, value: string]] = nil;
             cb: proc(event: JsonNode): bool) {.async.} =
  ## Get container events from docker, either in real time via streaming, or 
  ## via polling (using since). see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#monitor-docker-s-events>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` 
  ## or `DockerError`.
  ##
  ## Request parameters:
  ##
  ## * ``since`` - Timestamp used for polling.
  ## * ``until`` - Timestamp used for polling.
  ## * ``filters`` - The filters  to process on the event list. Available filters: 
  ##   * `container=<string>` - container to filter
  ##   * `event=<string>` - event to filter
  ##   * `image=<string>` - image to filter
  ##   * `label=<string>` - image and container label to filter
  ##   * `type=<string>` -- either container or image or volume or network
  ##   * `volume=<string>` -- volume to filter
  ##   * `network=<string>` -- network to filter
  ## * ``cb`` - Handle the return events. Events example:
  ##   
  ##   .. code-block:: nim
  ##
  ##     {"status":"pull","id":"busybox:latest","time":1442421700,"timeNano":1442421700598988358}
  ##     {"status":"create","id":"5745704abe9caa5","from":"busybox","time":1442421716,"timeNano":1442421716853979870}
  ##     {"status":"attach","id":"5745704abe9caa5","from":"busybox","time":1442421716,"timeNano":1442421716894759198}
  ##     {"status":"start","id":"5745704abe9caa5","from":"busybox","time":1442421716,"timeNano":1442421716983607193}
  proc callback(chunk: string): bool = 
    try:
      result = cb(parseJson(chunk))
    except:
      raise newException(ServerError, getCurrentExceptionMsg())

  var queries: seq[string] = @[]
  add(queries, "since", $since)
  if until > 0:
    add(queries, "until", $until)
  if filters != nil:
    var JFilters = newJObject()
    for i in filters:
      add(JFilters, i.key, %i.value)
    add(queries, "filters", $JFilters)
  let url = parseUri(c.scheme, c.hostname, c.port, "/events", queries)
  let res = await request(c, httpGET, url, 
                          cb = if cb == nil: nil else: callback)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc get*(c: AsyncDocker, name: string, cb: proc(data: string): bool) {.async.} =
  ## Get a tarball containing all images and metadata for the repository
  ## specified by `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-a-tarball-containing-all-images-in-a-repository>`_
  ##
  ## If name is a specific name and tag (e.g. ubuntu:latest), then only 
  ## that image (and its parents) are returned. If name is an image ID, 
  ## similarly only that image (and its parents) are returned, but with 
  ## the exclusion of the ‘repositories’ file in the tarball, as there
  ## were no image names referenced.
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` 
  ## or `DockerError`.  
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The image name and tag (e.g. ubuntu:latest) or image id.
  let url = parseUri(c.scheme, c.hostname, c.port, "/images/" & name & "/get")
  let res = await request(c, httpGET, url, cb = cb)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc get*(c: AsyncDocker, names: seq[string], cb: proc(data: string): bool) {.async.} =
  ## Get a tarball containing all images and metadata for one or more repositories.
  ## see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#get-a-tarball-containing-all-images>`_
  ##
  ## For each value of the ``names`` parameter: if it is a specific name and tag
  ## (e.g. `ubuntu:latest`), then only that image (and its parents) are returned;
  ## if it is an image ID, similarly only that image (and its parents) are returned
  ## and there would be no names referenced in the ‘repositories’ file for this
  ## image ID.
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` 
  ## or `DockerError`.  
  ##
  ## Request parameters:
  ##
  ## * ``names`` - The images name and tag (e.g. ubuntu:latest) or images id.
  var queries: seq[string] = @[]
  for name in names:
    add(queries, "names", name)
  let url = parseUri(c.scheme, c.hostname, c.port, "/images/get", queries)
  let res = await request(c, httpGET, url, cb = cb)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc load(c: AsyncDocker, tarball: string) {.async.} =
  # TODO: ...
  ## Load a set of images and tags into a Docker repository. see `DOcker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#load-a-tarball-with-a-set-of-images-and-tags-into-docker>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` 
  ## or `DockerError`.  
  let url = parseUri(c.scheme, c.hostname, c.port, "/images/load")
  let res = await request(c, httpPOST, url, body = tarball)
  case res.statusCode:
  of 200:
    discard
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc execCreate*(c: AsyncDocker; name: string;
                 attachStdin, attachStdout, attachStderr, tty = false;
                 detachKeys = "";
                 cmd: seq[string] = nil): Future[JsonNode] {.async.} =
  ## Sets up an exec instance in a running container `name`. see `Docker Reference <ttps://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#exec-create>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ConflictError``
  ## ``ServerError`` or `DockerError`.   
  ##
  ## Request patameters: 
  ##
  ## * ``name`` - The container name or id.
  ## * ``attachStdin`` - Boolean value, attaches to `stdin`.
  ## * ``attachStdout`` - Boolean value, attaches to `stdout`.
  ## * ``attachStderr`` - Boolean value, attaches to `stderr`.
  ## * ``tty`` - Boolean value, Attach standard streams to a `tty`, including `stdin` if it
  ##   is not closed.
  ## * ``detachKeys`` - Override the key sequence for detaching a container. Format is 
  ##   a single character [a-Z] or ctrl-<value> where <value> is one of: a-z, @, ^, [, , or _.
  ## * ``cmd`` - Command to run.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example: 
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Id": "f90e34656806",
  ##     "Warnings":[]
  ##   }
  var jBody = newJObject()
  add(jBody, "AttachStdin", %attachStdin)
  add(jBody, "AttachStdout", %attachStdout)
  add(jBody, "AttachStderr", %attachStderr)
  add(jBody, "Tty", %tty)
  add(jBody, "DetachKeys", %detachKeys)
  add(jBody, "Cmd", cmd)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/containers/" & name & "/exec")
  var headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 201:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc execStart*(c: AsyncDocker; name: string; 
                detach, tty = false;
                cb: proc(data: string): bool) {.async.} =
  ## Starts a previously set up `exec` instance `name`. If detach is true, this
  ## API returns after starting the `exec` command. Otherwise, this API sets
  ## up an interactive session with the `exec` command. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#exec-start>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## `ConflictError` or `DockerError`.    
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The exec instance id.
  ## * ``detach`` - Detach from the exec command.
  ## * ``tty`` - Boolean value to allocate a pseudo-TTY.
  var jBody = newJObject()
  add(jBody, "Detach", %detach)
  add(jBody, "Tty", %tty)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/exec/" & name & "/start")
  var headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody, cb = cb)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  else:
    raise newException(DockerError, res.body)

proc execResize*(c: AsyncDocker; name: string; width, height: int) {.async.} =
  ## Resizes the `tty` session used by the `exec` command id. The unit
  ## is number of characters. This API is valid only if `tty` was specified
  ## as part of creating and starting the `exec` command. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#exec-resize>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## `ConflictError` or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``width`` - Width of tty session.
  ## * ``height`` - Height of tty session.
  ##
  ## 
  var queries: seq[string] = @[]
  add(queries, "w", $width)
  add(queries, "h", $height)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/exec/" & name & "/resize", queries)
  let res = await request(c, httpPOST, url)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  else:
    raise newException(DockerError, res.body)
    
proc execInspect*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Resizes the `tty` session used by the `exec` command id. The unit
  ## is number of characters. This API is valid only if `tty` was specified
  ## as part of creating and starting the `exec` command. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#exec-resize>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## ``ServerError`` or `DockerError`.  
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "ID" : "11fb006128e8ceb3942e7c58d77750f24210e35f879dd204ac975c184b820b39",
  ##     "Running" : false,
  ##     "ExitCode" : 2,
  ##     "ProcessConfig" : {
  ##       "privileged" : false,
  ##       "user" : "",
  ##       "tty" : false,
  ##       "entrypoint" : "sh",
  ##       "arguments" : [
  ##         "-c",
  ##         "exit 2"
  ##       ]
  ##     },
  ##     "OpenStdin" : false,
  ##     "OpenStderr" : false,
  ##     "OpenStdout" : false,
  ##     "Container" : {
  ##       "State" : {
  ##         "Status" : "running",
  ##         "Running" : true,
  ##         "Paused" : false,
  ##         "Restarting" : false,
  ##         "OOMKilled" : false,
  ##         "Pid" : 3650,
  ##         "ExitCode" : 0,
  ##         "Error" : "",
  ##         "StartedAt" : "2014-11-17T22:26:03.717657531Z",
  ##         "FinishedAt" : "0001-01-01T00:00:00Z"
  ##       },
  ##       "ID" : "8f177a186b977fb451136e0fdf182abff5599a08b3c7f6ef0d36a55aaf89634c",
  ##       "Created" : "2014-11-17T22:26:03.626304998Z",
  ##       "Path" : "date",
  ##       "Args" : [],
  ##       "Config" : {
  ##         "Hostname" : "8f177a186b97",
  ##         "Domainname" : "",
  ##         "User" : "",
  ##         "AttachStdin" : false,
  ##         "AttachStdout" : false,
  ##         "AttachStderr" : false,
  ##         "ExposedPorts" : null,
  ##         "Tty" : false,
  ##         "OpenStdin" : false,
  ##         "StdinOnce" : false,
  ##         "Env" : [ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ],
  ##         "Cmd" : [
  ##           "date"
  ##         ],
  ##         "Image" : "ubuntu",
  ##         "Volumes" : null,
  ##         "WorkingDir" : "",
  ##         "Entrypoint" : null,
  ##         "NetworkDisabled" : false,
  ##         "MacAddress" : "",
  ##         "OnBuild" : null,
  ##         "SecurityOpt" : null
  ##       },
  ##       "Image" : "5506de2b643be1e6febbf3b8a240760c6843244c41e12aa2f60ccbb7153d17f5",
  ##       "NetworkSettings": {
  ##           "Bridge": "",
  ##           "SandboxID": "",
  ##           "HairpinMode": false,
  ##           "LinkLocalIPv6Address": "",
  ##           "LinkLocalIPv6PrefixLen": 0,
  ##           "Ports": null,
  ##           "SandboxKey": "",
  ##           "SecondaryIPAddresses": null,
  ##           "SecondaryIPv6Addresses": null,
  ##           "EndpointID": "",
  ##           "Gateway": "",
  ##           "GlobalIPv6Address": "",
  ##           "GlobalIPv6PrefixLen": 0,
  ##           "IPAddress": "",
  ##           "IPPrefixLen": 0,
  ##           "IPv6Gateway": "",
  ##           "MacAddress": "",
  ##           "Networks": {
  ##               "bridge": {
  ##                   "EndpointID": "",
  ##                   "Gateway": "",
  ##                   "IPAddress": "",
  ##                   "IPPrefixLen": 0,
  ##                   "IPv6Gateway": "",
  ##                   "GlobalIPv6Address": "",
  ##                   "GlobalIPv6PrefixLen": 0,
  ##                   "MacAddress": ""
  ##               }
  ##           }
  ##       },
  ##       "ResolvConfPath" : "/var/lib/docker/containers/8f177a186b977fb451136e0fdf182abff5599a08b3c7f6ef0d36a55aaf89634c/resolv.conf",
  ##       "HostnamePath" : "/var/lib/docker/containers/8f177a186b977fb451136e0fdf182abff5599a08b3c7f6ef0d36a55aaf89634c/hostname",
  ##       "HostsPath" : "/var/lib/docker/containers/8f177a186b977fb451136e0fdf182abff5599a08b3c7f6ef0d36a55aaf89634c/hosts",
  ##       "LogPath": "/var/lib/docker/containers/1eb5fabf5a03807136561b3c00adcd2992b535d624d5e18b6cdc6a6844d9767b/1eb5fabf5a03807136561b3c00adcd2992b535d624d5e18b6cdc6a6844d9767b-json.log",
  ##       "Name" : "/test",
  ##       "Driver" : "aufs",
  ##       "ExecDriver" : "native-0.2",
  ##       "MountLabel" : "",
  ##       "ProcessLabel" : "",
  ##       "AppArmorProfile" : "",
  ##       "RestartCount" : 0,
  ##       "Mounts" : []
  ##     }
  ##   }
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/exec/" & name & "/json")
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc volumes*(c: AsyncDocker, dangling = true): Future[JsonNode] {.async.} =
  ## List volumes. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#list-volumes>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError``
  ## or `DockerError`. 
  ##
  ## Request parameters:
  ##
  ## * ``dangling`` - Filters to process on the volumes list. There is one 
  ##   available filter: `dangling=true`
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Volumes": [
  ##       {
  ##         "Name": "tardis",
  ##         "Driver": "local",
  ##         "Mountpoint": "/var/lib/docker/volumes/tardis"
  ##       }
  ##     ]
  ##   }
  var queries: seq[string] = @[]
  var JFilters = newJObject()
  add(JFilters, "dangling", newJArray())
  add(JFilters["dangling"], %($dangling))
  add(queries, "filters", $JFilters)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/volumes", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc createVolume*(c: AsyncDocker, name: string, driver = "", 
                   driverOpts: seq[tuple[key, value: string]] = nil): Future[JsonNode] {.async.} =
  ## Create a volume. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#create-a-volume>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError``
  ## or `DockerError`.   
  ##
  ## Request parameters:
  ##
  ## * ``Name`` - The new volume’s name. If not specified, Docker generates a name.
  ## * ``driver`` - Name of the volume driver to use. Defaults to `local` for the name.
  ## * ``driverOpts`` - A mapping of driver options and values. These options are passed
  ##   directly to the driver and are driver specific.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Name": "tardis",
  ##     "Driver": "local",
  ##     "Mountpoint": "/var/lib/docker/volumes/tardis"
  ##   }
  ##
  ## * ``body`` - The JSON parameters. For example:
  ## 
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Name": "tardis"
  ##   }
  var jBody = newJObject()
  add(jBody, "Name", %name)
  add(jBody, "Driver", %driver)
  add(jBody, "DriverOpts", driverOpts)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/volumes/create")
  var headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 201:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc inspectVolume*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Return low-level information on the volume `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-a-volume>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``,
  ## ``ServerError`` or `DockerError`.  
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The volume name or id.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Name": "tardis",
  ##     "Driver": "local",
  ##     "Mountpoint": "/var/lib/docker/volumes/tardis"
  ##   }
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/volumes/" & name)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc rmVolume*(c: AsyncDocker, name: string) {.async.} =
  ## Instruct the driver to remove the volume `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-a-volume>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ConflictError``, 
  ## ``ServerError`` or `DockerError`.  
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The volume name or id.
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/volumes/" & name)
  let res = await request(c, httpDELETE, url)
  case res.statusCode:
  of 204:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 409:
    raise newException(ConflictError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc networks*(c: AsyncDocker, 
               nameFilters, idFilters, typeFilters: seq[string] = nil): 
              Future[JsonNode] {.async.} =
  ## List networks. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#list-networks>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``ServerError`` or ``DockerError``.
  ##
  ## Request parameters:
  ##
  ## * ``filters`` - Filters to process on the networks list. Available filters: 
  ##   `name=[network-names]` , `id=[network-ids]`.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: literal
  ##
  ##   [
  ##     {
  ##       "Name": "bridge",
  ##       "Id": "f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566",
  ##       "Scope": "local",
  ##       "Driver": "bridge",
  ##       "IPAM": {
  ##         "Driver": "default",
  ##         "Config": [
  ##           {
  ##             "Subnet": "172.17.0.0/16"
  ##           }
  ##         ]
  ##       },
  ##       "Containers": {
  ##         "39b69226f9d79f5634485fb236a23b2fe4e96a0a94128390a7fbbcc167065867": {
  ##           "EndpointID": "ed2419a97c1d9954d05b46e462e7002ea552f216e9b136b80a7db8d98b442eda",
  ##           "MacAddress": "02:42:ac:11:00:02",
  ##           "IPv4Address": "172.17.0.2/16",
  ##           "IPv6Address": ""
  ##         }
  ##       },
  ##       "Options": {
  ##         "com.docker.network.bridge.default_bridge": "true",
  ##         "com.docker.network.bridge.enable_icc": "true",
  ##         "com.docker.network.bridge.enable_ip_masquerade": "true",
  ##         "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
  ##         "com.docker.network.bridge.name": "docker0",
  ##         "com.docker.network.driver.mtu": "1500"
  ##       }
  ##     },
  ##     {
  ##       "Name": "none",
  ##       "Id": "e086a3893b05ab69242d3c44e49483a3bbbd3a26b46baa8f61ab797c1088d794",
  ##       "Scope": "local",
  ##       "Driver": "null",
  ##       "IPAM": {
  ##         "Driver": "default",
  ##         "Config": []
  ##       },
  ##       "Containers": {},
  ##       "Options": {}
  ##     },
  ##     {
  ##       "Name": "host",
  ##       "Id": "13e871235c677f196c4e1ecebb9dc733b9b2d2ab589e30c539efeda84a24215e",
  ##       "Scope": "local",
  ##       "Driver": "host",
  ##       "IPAM": {
  ##         "Driver": "default",
  ##         "Config": []
  ##       },
  ##       "Containers": {},
  ##       "Options": {}
  ##     }
  ##   ]
  var queries: seq[string] = @[]
  var jFilters = newJObject()
  if nameFilters != nil:
    var jNameFilters = newJArray()
    for i in nameFilters:
      add(jNameFilters, %i)
    add(jFilters, "name", jNameFilters)
  if idFilters != nil:
    var jIdFilters = newJArray()
    for i in idFilters:
      add(jIdFilters, %i)
    add(jFilters, "id", jIdFilters)
  if typeFilters != nil:
    var jTypeFilters = newJArray()
    for i in typeFilters:
      add(jTypeFilters, %i)
    add(jFilters, "type", jTypeFilters)
  add(queries, "filters", $jFilters)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks", queries)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result =  parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc inspectNetwork*(c: AsyncDocker, name: string): Future[JsonNode] {.async.} =
  ## Inspect network. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#inspect-network>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError`` or ``DockerError``.
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The network name or id.
  ## 
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Name": "bridge",
  ##     "Id": "f2de39df4171b0dc801e8002d1d999b77256983dfc63041c0f34030aa3977566",
  ##     "Scope": "local",
  ##     "Driver": "bridge",
  ##     "IPAM": {
  ##       "Driver": "default",
  ##       "Config": [
  ##         {
  ##           "Subnet": "172.17.0.0/16"
  ##         }
  ##       ]
  ##     },
  ##     "Containers": {
  ##       "39b69226f9d79f5634485fb236a23b2fe4e96a0a94128390a7fbbcc167065867": {
  ##         "EndpointID": "ed2419a97c1d9954d05b46e462e7002ea552f216e9b136b80a7db8d98b442eda",
  ##         "MacAddress": "02:42:ac:11:00:02",
  ##         "IPv4Address": "172.17.0.2/16",
  ##         "IPv6Address": ""
  ##       }
  ##     },
  ##     "Options": {
  ##       "com.docker.network.bridge.default_bridge": "true",
  ##       "com.docker.network.bridge.enable_icc": "true",
  ##       "com.docker.network.bridge.enable_ip_masquerade": "true",
  ##       "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
  ##       "com.docker.network.bridge.name": "docker0",
  ##       "com.docker.network.driver.mtu": "1500"
  ##     }
  ##   }
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks/" & name)
  let res = await request(c, httpGET, url)
  case res.statusCode:
  of 200:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  else:
    raise newException(DockerError, res.body)

proc createNetwork*(c: AsyncDocker, name: string, driver = "bridge",
                    ipamDriver = "", 
                    ipamConfig: seq[tuple[ipRange, subnet, gateway: string]] = nil, 
                    options: seq[tuple[key: string, value: bool]] = nil): Future[JsonNode] {.async.} =
  ## Create a network. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#create-a-network>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` or `DockerError`.
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The new network’s name. this is a mandatory field.
  ## * ``Driver`` - Name of the network driver to use. Defaults to `bridge` driver.
  ## * ``IPAM`` - Optional custom IP scheme for the network.
  ## * ``Options`` - Network specific options to be used by the drivers.
  ## * ``CheckDuplicate`` - Requests daemon to check for networks with same name.
  ##
  ## Result is a JSON object, the internal members of which depends on the version of your docker engine. For example:
  ##
  ## .. code-block:: nim
  ##
  ##   {
  ##     "Id": "22be93d5babb089c5aab8dbc369042fad48ff791584ca2da2100db837a1c7c30",
  ##     "Warning": ""
  ##   }
  var jBody = newJObject()
  add(jBody, "Name", %name)
  add(jBody, "Driver", %driver)
  var jOptions = newJObject()
  for i in options:
    add(jOptions, i.key, %($i.value))
  add(jBody, "Options", jOptions)
  var JIPAM = newJObject()
  add(JIPAM, "Driver", %ipamDriver)
  add(JIPAM, "Config", newJArray())
  for i in ipamConfig:
    var j = newJObject()
    add(j, "IPRange", %i.ipRange)
    add(j, "Gateway", %i.gateway)
    add(j, "Subnet", %i.subnet)
    add(JIPAM["Config"], j)
  add(jBody, "IPAM", JIPAM)
  # add(jBody, "CheckDuplicate", %checkDuplicate) TODO: is this support?
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks/create")
  let headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 201:
    try:
      result = parseJson(res.body)
    except:
      raise newException(ServerError, getCurrentExceptionMsg())
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)
  
proc connect*(c: AsyncDocker; name, container: string;
              iPv4Address, iPv6Address = "") {.async.} =
  ## Connects a container to a network. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#connect-a-container-to-a-network>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError``
  ## or ``DockerError``.
  ##
  ## * ``name`` - The new network’s name or id.
  ## * ``container`` - The container-id/name to be connected to the network.
  ## 
  ## ``FutureError`` represents an exception, it may be ``NotFoundError`` or `DockerError`.
  ##
  ## Docs: https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#connect-a-container-to-a-network
  var jBody = newJObject()
  add(jBody, "Container", %container)
  var jEndpointConfig = newJObject()
  add(jEndpointConfig, "IPAMConfig", newJObject())
  add(jEndpointConfig["IPAMConfig"], "IPv4Address", %iPv4Address)
  add(jEndpointConfig["IPAMConfig"], "IPv6Address", %iPv6Address)
  add(jBody, "EndpointConfig", jEndpointConfig)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks/" & name & "/connect")
  let headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody) 
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc disconnect*(c: AsyncDocker; name, container: string; force = false) {.async.} =
  ## Disconnects a container from a network. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#disconnect-a-container-from-a-network>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError``
  ## or ``DockerError``.
  ##
  ## Request parameters:
  ##
  ## * ``name`` - The new network’s name or id.
  ## * ``container`` - The container-id/name to be connected to the network.
  ## * ``Force`` - Force the container to disconnect from a network.
  var jBody = newJObject()
  add(jBody, "Container", %container)
  add(jBody, "Force", %force)
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks/" & name & "/disconnect")
  let headers = newStringTable({"Content-Type":"application/json"})
  let res = await request(c, httpPOST, url, headers, $jBody)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)

proc rmNetWork*(c: AsyncDocker, name: string) {.async.} =
  ## Instruct the driver to remove the network `name`. see `Docker Reference <https://docs.docker.com/engine/reference/api/docker_remote_api_v1.22/#remove-a-network>`_
  ##
  ## ``FutureError`` represents an exception, it may be ``NotFoundError``, ``ServerError`` or ``DockerError``.
  ##
  ## Request parameters：
  ## 
  ## * ``name`` - The new network’s name or id.
  let url = parseUri(c.scheme, c.hostname, c.port, 
                     "/networks/" & name)
  let res = await request(c, httpDELETE, url)
  case res.statusCode:
  of 200:
    discard
  of 404:
    raise newException(NotFoundError, res.body)
  of 500:
    raise newException(ServerError, res.body)
  else:
    raise newException(DockerError, res.body)











