This module implements an Docker Engine client based on Docker Remotet API. It's
asynchronous (non-blocking) that it can be used to write web services for deploying
swarm cluster and containers automatically on cloud environment. Of course, it
can also be used to write any local deployment tools. see [**API Documentation**](http://tulayang.github.io/asyncdocker.html)

See [tests](https://github.com/tulayang/asyncdocker/blob/master/tests/test.nim) and [test_ssl](https://github.com/tulayang/asyncdocker/blob/master/tests/test_ssl.nim) to get started; [deploy docker](https://github.com/tulayang/asyncdocker/blob/master/tests/deploy_nossl_docker.sh) and [deploy tls docker](https://github.com/tulayang/asyncdocker/blob/master/tests/deploy_ssl_docker.sh) to deploy docker daemon automatically.

```sh
nimble install asyncdocker
```

Docker CLI vs Asyncdocker 
-------------------------

The docker cli example:

```sh
  export DOCKER_HOST=127.0.0.1:2375
  docker create --name hello --hostname 192.168.0.1 \
                ubuntu:14.04 /bin/bash -c 'echo hello'
  docker start hello
```

And the equivalent asyncdocker example:

```nim
  import asyncdocker, asyncdispatch, json

  proc main() {.async.} = 
    var docker = newAsyncDocker("127.0.0.1", Port(2375))
    var ret = await docker.create(image = "ubuntu:14.04", 
                                  name = "hello",
                                  hostname = "192.168.0.1",
                                  cmd = @["/bin/bash", "-c", "echo hello"])
    echo "Container Id: ", ret["Id"].getStr()
    await docker.start(name = "hello")
    docker.close()

  waitFor main()
```

Simulate Pull Image
-------------------

This example simulates the docker cli ``docker pull ubuntu:14.10`` to download
the image and print progress bars:

```nim
import asyncdocker, asyncdispatch, json

const
  hostname = "127.0.0.1"
  port = Port(2375)

proc pullCb(state: JsonNode): Future[bool] {.async.} = 
  if state.hasKey("progress"):
    let current = state["progressDetail"]["current"].getNum()
    let total = state["progressDetail"]["total"].getNum()
    stdout.write("\r")
    stdout.write(state["id"].getStr())
    stdout.write(": ")
    stdout.write(state["status"].getStr())
    stdout.write(" ")
    stdout.write($current & "/" & $total)
    stdout.write(" ")
    stdout.write(state["progress"].getStr())
    if current == total:
      stdout.write("\n")
    stdout.flushFile()
  else:
    if state.hasKey("id"):
      stdout.write(state["id"].getStr())
      stdout.write(": ")
      stdout.write(state["status"].getStr())
      stdout.write("\n")
    else: 
      stdout.write(state["status"].getStr())
      stdout.write("\n")

proc main() {.async.} =
  var docker = newAsyncDocker(hostname, port)
  await docker.pull(fromImage = "ubuntu", tag = "14.10", cb = pullCb)          
  docker.close()

waitFor main()
```

output:

```nim
14.10: Pulling from library/ubuntu
b0efe5c05b4c: Pulling fs layer
0a1f1b169319: Pulling fs layer
1ceb0a3c7c48: Pulling fs layer
a3ed95caeb02: Pulling fs layer
a3ed95caeb02: Waiting
1ceb0a3c7c48: Downloading 682/682 [==================================================>]    682 B/682 B
1ceb0a3c7c48: Verifying Checksum
1ceb0a3c7c48: Download complete
a3ed95caeb02: Downloading 32/32 [==================================================>]     32 B/32 BB/77.8 kB
a3ed95caeb02: Verifying Checksum
a3ed95caeb02: Download complete
0a1f1b169319: Downloading 77797/77797 [==================================================>]  77.8 kB/77.8 kB
0a1f1b169319: Verifying Checksum
0a1f1b169319: Download complete
b0efe5c05b4c: Downloading 4848810/68321236 [===>                                               ] 4.849 MB/68.32 MB
```

Web Service
-----------

You can write a web service with ``asynchttpserver``:

```nim
  import asyncdocker, asyncdispatch, asynchttpserver, json

  var server = newAsyncHttpServer()

  proc cb(req: Request) {.async.} =
    var docker = newAsyncDocker("127.0.0.1", Port(2375))
    var pass = true
    try:
      var ret = await docker.create(image = "ubuntu:14.04", 
                                    name = "hello",
                                    hostname = "192.168.0.1",
                                    cmd = @["/bin/bash", "-c", "echo", "hello"])
      echo "Container Id: ", ret["Id"].getStr()
      await docker.start(name = "hello")
      await req.respond(Http201, "OK")
    except:
      pass = false
    if not pass:
      await req.respond(Http500, "Failure")
    docker.close()

  waitFor server.serve(Port(8080), cb)
```

or with ``jester``:

```nim
  import asyncdocker, asyncdispatch, asynchttpserver, json, jester

  routes:
    post "/containers/@name/run"
      var docker = newAsyncDocker("127.0.0.1", Port(2375))
      var pass = true
      try:
        var ret = await docker.create(image = "ubuntu:14.04", 
                                      name = @"name",
                                      hostname = "192.168.0.1",
                                      cmd = @["/bin/bash", "-c", "echo", "hello"])
        echo "Container Id: ", ret["Id"].getStr()
        await docker.start(name = "hello")
        await req.respond(Http201, "OK")
      except:
        pass = false
      if not pass:
        await req.respond(Http500, "Failure")
      docker.close()
```

Stream support
--------------

Supports to stream responses from the docker daemon with ``attach``, ``logs``, 
``execStart``, etc. For example:

```sh
docker logs --follow hello
```

equivalent to:

```nim
proc logsCb(): proc(stream: int, log: string): Future[bool] = 
  var i = 0
  proc cb(stream: int, log: string): Future[bool] {.async.} = 
    if stream == 1:
      stdout.write("stdout: " & log)
    if stream == 2:
      stderr.write("stderr: " & log)
    echo i
    if i == 5:
     result = true # Close socket to stop receiving logs.
    inc(i)
  result = cb

await docker.logs("hello", follow = true, cb = logsCb())
```

TLS Verify
----------

Supports `--tls` and `--tlsverify` to protect docker daemon socket. 

This requires the OpenSSL library, fortunately it's widely used and installed on 
many operating systems. Client will use SSL automatically if you give any of 
the functions a url with the ``https`` schema, for example: ``https://github.com/``,
you also have to compile with ``ssl`` defined like so: ``nim c -d:ssl ...``.   

For `--tls`: 

```sh
  docker --host 127.0.0.1:2376 \
         --tls \
         --tlskey /home/docker/.docker/key.pem \
         --tlscert /home/docker/.docker/cert.pem \
         ps
```

equivalent to: 

```nim
  import asyncdocker, asyncdispatch, json, openssl

  const
    key = "/home/docker/.docker/key.pem"
    cert = "/home/docker/.docker/cert.pem"
  
  proc main() {.async.}
    var docker = newAsyncDocker("127.0.0.1", Port(2376), nil, key, cert, CVerifyNone)
    var containers = await docker.ps()

  waitFor main()
```

For `--tlsverify`: 

```sh
  docker --host 127.0.0.1:2376 \
         --tlsverify \
         --tlscacert /home/docker/.docker/ca.pem \
         --tlskey /home/docker/.docker/key.pem \
         --tlscert /home/docker/.docker/cert.pem \
         ps   
```

equivalent to: 

```nim
  import asyncdocker, asyncdispatch, json, openssl

  const
    cacert = "/home/docker/.docker/ca.pem"
    key = "/home/docker/.docker/key.pem"
    cert = "/home/docker/.docker/cert.pem"
  
  proc main() {.async.}
    var docker = newAsyncDocker("127.0.0.1", Port(2376), cacert, key, cert, CVerifyPeer)
    var containers = await docker.ps()

  waitFor main()
```

Swarm cluster support
---------------------

The Docker Swarm API is mostly compatible with the Docker Remote API. see [Docker Swarm Reference](https://docs.docker.com/swarm/swarm-api/)

[**API Documentation**](http://tulayang.github.io/asyncdocker.html)
