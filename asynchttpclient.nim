#
#          Nim's Unofficial Library
#        (c) Copyright 2016 Wang Tong
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#
## This module implements a common http/https client that can be used for docker 
## and cloud request.
##
## Supporting "Transfer-Encoding: chunk", so user can provide a callback to process 
## streaming datas.
## 
## Asynchronous HTTP requests
## ==========================
##
## You simply have to create a new instance of the ``AsyncHttpClient`` object.
## You may then use ``await`` on the functions defined for that object.
## Keep in mind that the following code needs to be inside an asynchronous procedure.
##
## .. code-block::nim
##
##    var client = newAsyncHttpClient()
##    var resp = await client.request("http://google.com")
##
## SSL/TLS support
## ===============
##
## This requires the OpenSSL library, fortunately it's widely used and installed on 
## many operating systems. Client will use SSL automatically if you give any of 
## the functions a url with the ``https`` schema, for example: ``https://github.com/``,
## you also have to compile with ``ssl`` defined like so: ``nim c -d:ssl ...``.

import asyncdispatch, asyncnet, strtabs, uri, strutils, parseutils, net

type
  ProtocolError* = object of IOError ## Exception that is raised when server does 
                                     ## not conform to the implemented protocol. 
  RequestError* = object of IOError  ## Throwning when the server returns an error.

  HttpMethod* = enum  ## The requested HttpMethod.
    httpHEAD,         ## Asks for the response identical to the one that would
                      ## correspond to a GET request, but without the response
                      ## body.
    httpGET,          ## Retrieves the specified resource.
    httpPOST,         ## Submits data to be processed to the identified
                      ## resource. The data is included in the body of the
                      ## request.
    httpPUT,          ## Uploads a representation of the specified resource.
    httpDELETE,       ## Deletes the specified resource.
    httpTRACE,        ## Echoes back the received request, so that a client
                      ## can see what intermediate servers are adding or
                      ## changing in the request.
    httpOPTIONS,      ## Returns the HTTP methods that the server supports
                      ## for specified address.
    httpCONNECT       ## Converts the request connection to a transparent
                      ## TCP/IP tunnel, usually used for proxies.

  AsyncHttpClient* = ref object ## The asynchronous http/https client object.
    socket: AsyncSocket
    connected: bool
    userAgent: string
    currentURL: Uri
    when defined(ssl):
      sslContext: net.SslContext

  Response* = tuple
    version: string
    statusCode: int
    reasonPhrase: string
    headers: StringTableRef
    body: string

  ResponsePhase = enum
    rpProtocol, rpHeaders, rpBody

  Callback* = proc(chunk: string): Future[bool]

when not defined(ssl):
  type SSLContext = ref object
  let defaultSSLContext: SSLContext = nil
else:
  let defaultSSLContext = newContext(verifyMode = CVerifyNone)

const userAgent* = "Nim async client/0.0.1 (0.13.0)"

proc newAsyncHttpClient*(userAgent = userAgent, 
                         sslContext = defaultSslContext): AsyncHttpClient =
  ## Creates a new AsyncHttpClient instance.
  new(result)
  result.connected = false
  result.userAgent = userAgent
  when defined(ssl):
    result.sslContext = SslContext(sslContext)

proc close*(client: AsyncHttpClient) =
  ## Closes any connections held by the HTTP client.
  if client.connected:
    close(client.socket)
    client.connected = false

proc connect(client: AsyncHttpClient, url: Uri) {.async.} =
  client.socket = newAsyncSocket()
  let port =
    if url.port == "":
      if toLower(url.scheme) == "https":
        Port(443)
      else:
        Port(80)
    else: 
      Port(parseInt(url.port))
  if toLower(url.scheme) == "https":
    when defined(ssl):
      wrapSocket(client.sslContext, client.socket)
    else:
      raise newException(RequestError,
                         "SSL support is not available. Cannot connect over SSL.")
  await connect(client.socket, url.hostname, port)
  client.currentURL = url
  client.connected = true

proc generateHeaders(httpMethod: string, url: Uri,
                     headers: StringTableRef, body: string): string =
  result = ""
  add(result, httpMethod)
  add(result, ' ')
  if url.path[0] != '/':
    add(result, '/')
  add(result, url.path)
  if len(url.query) > 0:
    add(result, "?")
    add(result, url.query)
  add(result, " HTTP/1.1")
  add(result, "\c\L")
  if url.port == "":
    add(result, "Host: ")
    add(result, url.hostname)
    add(result, "\c\L")
  else:
    add(result, "Host: ")
    add(result, url.hostname)
    add(result, ":")
    add(result, url.port)
    add(result, "\c\L")
  # add(result, "Connection: Keep-Alive")
  # add(result, "\c\L")
  if body != nil and body != "" and 
     (headers == nil or not hasKey(headers, "Content-Length")):
    add(result, "Content-Length: ")
    add(result, $len(body))
    add(result, "\c\L")
  if headers != nil:
    for key, val in headers:
      add(result, key)
      add(result, ": ")
      add(result, val)
      add(result, "\c\L")
  add(result, "\c\L")

proc recvFull(socket: AsyncSocket, size: int): Future[string] {.async.} =
  ## Ensures that all the data requested is read and returned.
  result = ""
  while true:
    if size <= len(result): 
      break
    let data = await recv(socket, size - len(result))
    if data == "": 
      break # We've been disconnected.
    add(result, data)

proc parseChunks(client: AsyncHttpClient, 
                 cb: Callback = nil): Future[string] {.async.} =
  if cb == nil:
    result = ""
  while true:
    var chunkSize = 0
    var chunkSizeStr = await recvLine(client.socket)
    var i = 0
    if chunkSizeStr == "":
      close(client)
      raise newException(ProtocolError, 
                         "connection was closed before full request has been made")
    while true:
      case chunkSizeStr[i]
      of '0'..'9':
        chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('0'))
      of 'a'..'f':
        chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('a') + 10)
      of 'A'..'F':
        chunkSize = chunkSize shl 4 or (ord(chunkSizeStr[i]) - ord('A') + 10)
      of '\0':
        break
      of ';':
        # http://tools.ietf.org/html/rfc2616#section-3.6.1
        # We don't care about chunk-extensions.
        break
      else:
        raise newException(ProtocolError, "Invalid chunk size: " & chunkSizeStr)
      inc(i)
    if chunkSize <= 0:
      discard await recvFull(client.socket, 2) # Skip \c\L
      break
    let chunk = await recvFull(client.socket, chunkSize)
    discard await recvFull(client.socket, 2) # Skip \c\L
    # Streaming report the chunk data.
    if cb == nil:
      add(result, chunk)
    else:
      if (await cb(chunk)):
        close(client)
        break

proc parseVndStream(client: AsyncHttpClient, 
                    cb: Callback = nil): Future[string] {.async.} =
  var buf = ""
  if cb == nil:
    result = ""
  while true:
    buf = await recvLine(client.socket)
    if buf == "": 
      close(client)
      break
    if cb == nil:
      add(result, buf & "\L")
    else:
      if (await cb(buf & "\L")):
        close(client)
        break

proc parseResponse(client: AsyncHttpClient, getBody: bool, 
                   cb: Callback = nil): Future[Response] {.async.} =
  var fullyRead = false
  var phase = rpProtocol
  result.headers = newStringTable(modeCaseInsensitive)

  while true:
    case phase:
    of rpProtocol:
      var lineAt = 0
      var line = await recvLine(client.socket)
      if line == "":  # We've been disconnected. 
        close(client)
        raise newException(ProtocolError, 
                           "connection was closed before full request has been made")
      var n = skipIgnoreCase(line, "HTTP/", lineAt)
      if n <= 0:
        raise newException(ProtocolError, "invalid http version")
      inc(lineAt, n)
      n = skipIgnoreCase(line, "1.1", lineAt)
      if n > 0: 
        result.version = "1.1"
      else:
        n = skipIgnoreCase(line, "1.0", lineAt)
        if n <= 0: 
          raise newException(ProtocolError, "unsupported http version")
        result.version = "1.0"
      inc(lineAt, n)
      inc(lineAt, skipWhitespace(line, lineAt))
      n = parseInt(line, result.statusCode, lineAt)
      if n != 3:
        raise newException(ProtocolError, "invalid status code")
      inc(lineAt, n)
      inc(lineAt, skipWhitespace(line, lineAt))
      result.reasonPhrase = line[lineAt..^1]
      phase = rpHeaders
    of rpHeaders:
      var lineAt = 0
      var line = await recvLine(client.socket)
      if line == "":  # We've been disconnected. 
        close(client)
        raise newException(ProtocolError, 
                           "connection was closed before full request has been made")
      if line == "\c\L":
        phase = rpBody
        continue
      var name = ""
      var n = parseUntil(line, name, ':', lineAt)
      if n <= 0: 
        raise newException(ProtocolError, "invalid header")
      inc(lineAt, n)
      if line[lineAt] != ':': 
        raise newException(ProtocolError, "invalid header")
      inc(lineAt)
      result.headers[name] = strip(line[lineAt..^1])
    of rpBody:
      if getBody:
        var body: string
        if getOrDefault(result.headers, "Transfer-Encoding") == "chunked":
          result.body = await parseChunks(client, cb)
        elif getOrDefault(result.headers, "Content-Type") == "application/vnd.docker.raw-stream":
          result.body = await parseVndStream(client, cb)
        else:
          # -REGION- Content-Length
          # (http://tools.ietf.org/html/rfc2616#section-4.4) NR.3
          var contentLengthHeader = getOrDefault(result.headers, "Content-Length")
          if contentLengthHeader != "":
            var length = parseInt(contentLengthHeader)
            if length > 0:
              body = await recvFull(client.socket, length)
              if body == "":
                close(client)
                raise newException(ProtocolError, 
                                   "connection was closed before full request has been made")
              if len(body) != length:
                close(client)
                raise newException(ProtocolError, 
                                   "received length doesn't match expected length, wanted " &
                                   $length & " got " & $len(body))
              if cb == nil:
                shallowCopy(result.body, body)
              elif (await cb(body)):
                close(client)
          else:
            if getOrDefault(result.headers, "Connection") == "close":
              body = ""
              var buf = ""
              while true:
                buf = await recv(client.socket, BufferSize)
                if buf == "": 
                  break
                add(body, buf)
              close(client)
              if cb == nil:
                shallowCopy(result.body, body)
              else:
                discard (await cb(body))
      break

proc request*(client: AsyncHttpClient, httpMethod: string, url: Uri, 
              headers: StringTableRef = nil, body: string = nil, 
              cb: Callback = nil): Future[Response] {.async.} =
  ## Connects to the hostname specified by the ``Uri`` and performs a request
  ## using the custom method string specified by ``httpMethod``.
  ##
  ## If the encoding of response data is "Transfer-Encoding: chunk", you can 
  ## specify ``cb`` to process the data like a stream.
  ##
  ## Connection will kept alive. Further requests on the same ``client`` to
  ## the same hostname will not require a new connection to be made. The
  ## connection can be closed by using the ``close`` procedure.
  ##
  ## The returned future will complete once the request is completed.
  if client.currentURL.hostname != url.hostname or
     client.currentURL.port != url.port or
     client.currentURL.scheme != url.scheme:
    if client.connected: 
      close(client)
    client.socket = newAsyncSocket()
    await connect(client, url)
  elif not client.connected:
    client.socket = newAsyncSocket()
    await connect(client, url)
  if headers != nil and not hasKey(headers, "User-Agent") and 
     client.userAgent != nil and client.userAgent != "":
    headers["User-Agent"] = client.userAgent
  var headerBytes = generateHeaders(httpMethod, url, headers, body)
  await send(client.socket, headerBytes)
  if body != nil and body != "":
    await send(client.socket, body)
  result = await parseResponse(client, httpMethod != "HEAD", cb)

proc request*(client: AsyncHttpClient, httpMethod: HttpMethod, url: Uri, 
              headers: StringTableRef = nil, body: string = nil,
              cb: Callback = nil): Future[Response] =
  ## Connects to the hostname specified by the ``Uri`` and performs a request
  ## using the method specified.
  ##
  ## If the encoding of response data is "Transfer-Encoding: chunk", you can 
  ## specify ``cb`` to process the data like a stream.
  ##
  ## Connection will kept alive. Further requests on the same ``client`` to
  ## the same hostname will not require a new connection to be made. The
  ## connection can be closed by using the ``close`` procedure.
  ##
  ## The returned future will complete once the request is completed.
  result = request(client, substr($httpMethod, len("http")), url, headers, body, cb)

when isMainModule:
  proc main() {.async.} =
    var client = newAsyncHttpClient()
    var res = await request(client, httpGET, parseUri("http://www.baidu.com"), 
                            newStringTable(modeCaseInsensitive))
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res.statusCode
    echo "Got response reason phrase: ", res.reasonPhrase
    echo "Got response headers: ", res.headers
    #echo "Got response body: ", res.body

    var res2 = await request(client, "GET", parseUri("http://www.baidu.com"))
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res2.statusCode
    echo "Got response reason phrase: ", res2.reasonPhrase
    echo "Got response headers: ", res2.headers
    #echo "Got response body: ", res2.body

    proc cb(chunk: string): Future[bool] {.async.} =
      write(stdout, "chunk: ") 
      await sleepAsync(1000)
      write(stdout, "data\n") 
      flushFile(stdout)

    var res3 = await request(client, "GET", parseUri("https://github.com/"), 
                             newStringTable(modeCaseInsensitive), cb = cb)
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res3.statusCode
    echo "Got response reason phrase: ", res3.reasonPhrase
    echo "Got response headers: ", res3.headers
    #echo "Got response body: ", res3.body

  waitFor main()
