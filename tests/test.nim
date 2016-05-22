import asyncdispatch, ../asyncdocker, json, os

const 
  hostname = "127.0.0.1"
  port = Port(2375)

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

proc exportContainerCb(): proc(data: string): Future[bool] = 
  var j = 1
  proc cb(data: string): Future[bool] {.async.} = 
    echo data
    if j == 10:
      result = true # Close socket to stop receiving datas.
    inc(j)
  result = cb

proc statsCb(): proc(data: JsonNode): Future[bool] = 
  var n = 1
  proc cb(data: JsonNode): Future[bool] {.async.} = 
    echo $data & "\n"
    if n == 2:
      result = true # Close socket to stop receiving datas.
    inc(n)
  result = cb

proc attachCb(): proc(stream: int, payload: string): Future[bool] = 
  var m = 1
  proc cb(stream: int, payload: string): Future[bool] {.async.} = 
    if stream == 1:
      stdout.write("stdout: " & payload)
    if stream == 2:
      stderr.write("stderr: " & payload)
    if m == 5:
      result = true # Close socket to stop receiving payloads.
    inc(m)
  result = cb

proc getArchiveCb(chunk: string): Future[bool] {.async.} = 
  echo chunk

proc buildCb(state: JsonNode): Future[bool] {.async.} = 
  stdout.write(state["stream"].getStr())

proc eventsCb(): proc(event: JsonNode): Future[bool] = 
  var o = 1
  proc cb(event: JsonNode): Future[bool] {.async.} = 
    echo $event & "\n"
    if o == 2:
      result = true
    inc(o)
  result = cb

proc getCb(): proc(data: string): Future[bool] = 
  var a = 1
  proc cb(data: string): Future[bool] {.async.} = 
    echo data
    if a == 5:
      result = true
    inc(a)
  result = cb

proc getsCb(): proc(data: string): Future[bool] =
  var b = 1
  proc getsCb(data: string): Future[bool] {.async.} = 
    echo data
    if b == 5:
      result = true
    inc(b)

proc execStartCb(data: string): Future[bool] {.async.} = 
  echo "Date: ", data

proc main() {.async.} =
  var docker = newAsyncDocker(hostname, port)

  echo "\n==================== Pull Image ====================\n"
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
  await docker.pull(fromImage = "ubuntu", tag = "14.04", cb = pullCb)

  echo "\n=================== Ps Container ===================\n"
  var containers = await docker.ps(all = true, limit = 2, labelFilters = @["purpose=test"],
                                   statusFilters = @[statRunning, statCreated, statExited])
  echo containers

  var hello = await docker.create(image = "ubuntu:14.04",
                                  cmd = @["/bin/bash", "-c", "while true; do echo hello world; sleep 1; done"],
                                  name = "hello",
                                  labels = @[("purpose", "test")],
                                  exposedPorts = @["22/tcp"],
                                  binds = @["/tmp:/tmp:ro"],
                                  portBindings = @[("5000", @["5000"])])
  await docker.start(name = "hello")

  var testContainers1 = await docker.ps(all = true, labelFilters = @["purpose=test"])
  assert testContainers1[0]["Id"].getStr() == hello["Id"].getStr()

  var testContainers2 = await docker.ps(all = true, labelFilters = @["purpose"])
  assert testContainers2[0]["Id"].getStr() == hello["Id"].getStr()

  var helloInfo = await docker.inspect(name = "hello", size = true)
  assert helloInfo["Id"].getStr() == hello["Id"].getStr()
  assert helloInfo["Path"].getStr() == "/bin/bash"
  assert helloInfo["HostConfig"]["Binds"][0].getStr() == "/tmp:/tmp:ro"
  assert helloInfo["Mounts"][0]["Source"].getStr() == "/tmp"
  assert helloInfo["Mounts"][0]["Destination"].getStr() == "/tmp"
  assert helloInfo["Mounts"][0]["Mode"].getStr() == "ro"
  assert helloInfo["Mounts"][0]["RW"].getBval() == false
  await docker.restart(name = "hello")
  echo "\n=================== Top Container ==================\n"
  var top = await docker.top(name = "hello")
  echo top
  echo "\n====================================================\n"

  echo "\n================== Logs Container ==================\n"
  
  await docker.logs("hello", follow = true, cb = logsCb())

  echo "\n================= Export Container =================\n"
  await docker.exportContainer(name = "hello", cb = exportContainerCb())

  echo "\n================== Stats Container =================\n"
  await docker.stats(name = "hello", stream = true, cb = statsCb())

  discard await docker.changes("hello")

  await docker.resize(name = "hello", width = 100, height = 100)

  await docker.restart(name = "hello")
  await docker.kill(name = "hello")
  await docker.restart(name = "hello")

  echo "\n================= Update Container =================\n"
  var update = await docker.update("hello", cpuShares = 2)
  echo update

  await docker.rename(name = "hello", newname = "newhello")
  await docker.pause(name = "newhello")
  await docker.unpause(name = "newhello")
  await docker.rename(name = "newhello", newname = "hello")

  echo "\n================= Attach Container =================\n"
  await docker.attach("hello", stream = true, stdout = true, cb = attachCb())

  echo "\n================= Retrieve Archive =================\n"
  var archive = await docker.retrieveArchive(name = "hello", path = "/home")
  echo archive

  echo "\n==================== Get Archive ===================\n"
  echo await docker.getArchive(name = "hello", path = "/home", cb = getArchiveCb)

  await docker.putArchive(name = "hello", path = "/home",
                          archive = $(readFile(joinPath(getAppDir(), "put_archive.tar.gz"))))

  echo "\n======================== Images ======================\n"
  var images = await docker.images(all = true, danglingFilters = false)
  assert images.len() > 0

  echo "\n======================== Build =======================\n"
  await docker.build($readFile(joinPath(getAppDir(), "build.tar.gz")),
                     dockerfile = "Dockerfile",
                     cb = buildCb)

  var imageInfo = await docker.inspectImage(name = "ubuntu:14.04")
  echo imageInfo["RepoTags"][0]
  assert imageInfo["RepoTags"][0].getStr() == "ubuntu:14.04" 

  discard await docker.history(name = "ubuntu:14.04")

  await docker.tag(name = "ubuntu:14.04", repo = "asyncdocker/ubuntu", tag = "1.0")

  discard await docker.rmImage(name = "asyncdocker/ubuntu:1.0")

  var search = await docker.search("ubuntu")
  assert search.len() > 0

  echo "\n========================= Info ========================\n"
  var info = await docker.info()
  echo "Containers: ", $(info["Containers"].getNum())

  echo "\n======================= Version =======================\n"
  echo await docker.version()

  discard await docker.ping()

  var commit = await docker.commit(container = "hello", 
                                   repo = "asyncdocker/hello",
                                   tag = "1.0",
                                   workingDir = "/home")
  assert commit["Id"].getStr().len() > 0

  echo "\n======================== Events =======================\n"
  
  await docker.events(cb = eventsCb())

  echo "\n============== Get Tarball From Image =================\n"
  
  await docker.get(name = "ubuntu:14.04", cb = getCb())

  echo "\n============== Get Tarball From Images ================\n"
  
  await docker.get(names = @["ubuntu:14.04"], cb = getsCb())

  echo "\n================== Exec Container =====================\n"
  var exec = await docker.execCreate(name = "hello", attachStdin = false, attachStdout = true,
                                     attachStderr = false, tty = false, cmd = @["date"])
  
  await docker.execStart(name = getStr(exec["Id"]), tty = true, 
                         cb = execStartCb)

  #await docker.execResize(name = exec["Id"].getStr(), width = 100, height =200)

  var execInfo = await docker.execInspect(name = exec["Id"].getStr())
  assert execInfo["ID"].getStr() == exec["Id"].getStr()

  var volumes = await docker.volumes()

  var volume = await docker.createVolume(name = "newvolume", driver = "local")

  var volumeInfo = await docker.inspectVolume(name = "newvolume")
  assert volume["Name"].getStr() == volumeInfo["Name"].getStr()

  await docker.rmVolume(name = "newvolume") 

  var networks = await docker.networks(nameFilters = @["bridge"])
  assert networks.len() > 0

  var net1 = await docker.createNetwork(name = "net_1", ipamDriver = "default", 
                                        ipamConfig = @[("", "192.168.11.0/24", "192.168.11.2")],
                                        options = @[("com.docker.network.bridge.enable_icc", false)])
  var net1Info = await docker.inspectNetwork(name = "net_1")
  assert net1["Id"].getStr() == net1Info["Id"].getStr()
  
  await docker.connect(name = "net_1", container = "hello")
  await docker.disconnect(name = "net_1", container = "hello")
  await docker.rmNetWork("net_1")

  await docker.stop(name = "hello")
  await docker.rm(name = "hello")
  
  docker.close()

  echo "=========================================================\n"
  echo "Test complete ."

waitFor main()
