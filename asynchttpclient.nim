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

import asyncdispatch, asyncnet, strtabs, uri, strutils, parseutils, net, math

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

  Response* = tuple
    version: string
    statusCode: int
    reasonPhrase: string
    headers: StringTableRef

  ResponsePhase = enum
    rpProtocol, rpHeaders, rpBody

  ResponseBodyStatus* = enum
    rbsData, rbsEnd, rbsClose

  ResponseBodyKind* = enum
    rbkEntire, rbkChunked, rbkDockerVnd

  AsyncHttpClient* = ref object ## The asynchronous http/https client object.
    socket: AsyncSocket
    connected: bool
    userAgent: string
    currentUri: Uri
    resKind: ResponseBodyKind 
    when defined(ssl):
      sslContext: net.SslContext

  Callback* = proc(chunk: string): Future[bool]

when not defined(ssl):
  type SSLContext = ref object
  let defaultSSLContext: SSLContext = nil
else:
  let defaultSSLContext: SSLContext = nil

const userAgent* = "Nim async client/0.0.1 (0.13.0)"

proc newAsyncHttpClient*(userAgent = userAgent, 
                         sslContext = defaultSSLContext): AsyncHttpClient =
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

proc connect(client: AsyncHttpClient, httpUri: Uri) {.async.} =
  client.socket = newAsyncSocket()
  let port =
    if httpUri.port == "":
      if toLower(httpUri.scheme) == "https":
        Port(443)
      else:
        Port(80)
    else: 
      Port(parseInt(httpUri.port))
  if toLower(httpUri.scheme) == "https":
    when defined(ssl):
      wrapSocket(client.sslContext, client.socket)
    else:
      raise newException(RequestError,
                         "SSL support is not available. Cannot connect over SSL.")
  await connect(client.socket, httpUri.hostname, port)
  client.currentUri = httpUri
  client.connected = true

proc generateHeaders(httpMethod: string, httpUri: Uri,
                     headers: StringTableRef): string =
  result = ""
  add(result, httpMethod)
  add(result, ' ')
  if httpUri.path[0] != '/':
    add(result, '/')
  add(result, httpUri.path)
  if len(httpUri.query) > 0:
    add(result, "?")
    add(result, httpUri.query)
  add(result, " HTTP/1.1")
  add(result, "\c\L")
  if httpUri.port == "":
    add(result, "Host: ")
    add(result, httpUri.hostname)
    add(result, "\c\L")
  else:
    add(result, "Host: ")
    add(result, httpUri.hostname)
    add(result, ":")
    add(result, httpUri.port)
    add(result, "\c\L")
  # add(result, "Connection: Keep-Alive")
  # add(result, "\c\L")
  if headers != nil:
    for key, val in headers:
      add(result, key)
      add(result, ": ")
      add(result, val)
      add(result, "\c\L")
  add(result, "\c\L")

proc newConnection*(client: AsyncHttpClient, httpUri: Uri) {.async.} =
  if client.currentUri.hostname != httpUri.hostname or
     client.currentUri.port != httpUri.port or
     client.currentUri.scheme != httpUri.scheme:
    if client.connected: 
      close(client)
    client.socket = newAsyncSocket()
    await connect(client, httpUri)
  elif not client.connected:
    client.socket = newAsyncSocket()
    await connect(client, httpUri)

proc sendHeaders*(client: AsyncHttpClient, httpMethod: string, httpUri: Uri, 
                  headers: StringTableRef = nil) {.async.} = 
  await newConnection(client, httpUri)
  if headers != nil and not hasKey(headers, "User-Agent") and 
     client.userAgent != nil and client.userAgent != "":
    headers["User-Agent"] = client.userAgent
  await send(client.socket, generateHeaders(httpMethod, httpUri, headers))

proc sendHeaders*(client: AsyncHttpClient, httpMethod: HttpMethod, httpUri: Uri, 
                  headers: StringTableRef = nil): Future[void] = 
  sendHeaders(client, substr($httpMethod, len("http")), httpUri, headers)

proc sendBody*(client: AsyncHttpClient, body: string) {.async.} = 
  if body != nil and body != "":
    await send(client.socket, body)

proc sendChunk*(client: AsyncHttpClient, data: string) {.async.} =
  if data != nil and data != "":
    let dataLen = len(data)
    let sizeLen = Positive(floor(log2(toFloat(dataLen)) / 4 + 1))
    await send(client.socket, toHex(BiggestInt(dataLen), sizeLen) & "\r\n" & data & "\r\n")

proc endChunk*(client: AsyncHttpClient): Future[void] =
  send(client.socket, "0\r\n\r\n")   

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

proc recvHeaders*(client: AsyncHttpClient): Future[Response] {.async.} =
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
        break
      var name = ""
      var n = parseUntil(line, name, ':', lineAt)
      if n <= 0: 
        raise newException(ProtocolError, "invalid header")
      inc(lineAt, n)
      if line[lineAt] != ':': 
        raise newException(ProtocolError, "invalid header")
      inc(lineAt)
      result.headers[name] = strip(line[lineAt..^1])
    else:
      break
  if getOrDefault(result.headers, "Transfer-Encoding") == "chunked":
    client.resKind = rbkChunked
  elif getOrDefault(result.headers, "Content-Type") == "application/vnd.docker.raw-stream":
    client.resKind = rbkDockerVnd
  else:
    client.resKind = rbkEntire

proc parseChunk(client: AsyncHttpClient): 
               Future[tuple[status: ResponseBodyStatus, data: string]] {.async.} =
  result.status = rbsData
  result.data = ""
  var chunkSize = 0
  var chunkSizeStr = await recvLine(client.socket)
  var i = 0
  if chunkSizeStr == "":
    result.status = rbsClose
    return
    # raise newException(ProtocolError, 
    #                    "connection was closed before full request has been made")
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
    result.status = rbsEnd
    discard await recvFull(client.socket, 2) # Skip \c\L
    return
  result.data = await recvFull(client.socket, chunkSize)
  discard await recvFull(client.socket, 2) # Skip \c\L

proc parseDockerVnd(client: AsyncHttpClient): 
                   Future[tuple[status: ResponseBodyStatus, data: string]] {.async.} =
  result.status = rbsData
  result.data = await recvLine(client.socket)
  if result.data == "": 
    result.status = rbsClose
  else:
    result.data = result.data & "\L"

proc recvBody*(client: AsyncHttpClient, res: Response): 
              Future[tuple[status: ResponseBodyStatus, data: string]] {.async.} = 
  if client.resKind == rbkChunked:
    result = await parseChunk(client)
  elif client.resKind == rbkDockerVnd:
    result = await parseDockerVnd(client)
  else:
    result.status = rbsEnd
    result.data = ""
    # -REGION- Content-Length
    # (http://tools.ietf.org/html/rfc2616#section-4.4) NR.3
    let contentLengthHeader = getOrDefault(res.headers, "Content-Length")
    if contentLengthHeader != "":
      let length = parseInt(contentLengthHeader)
      if length > 0:
        result.data = await recvFull(client.socket, length)
        if result.data == "":
          result.status = rbsClose
          raise newException(ProtocolError, 
                             "got disconnected while trying to read body")
        if len(result.data) != length:
          result.status = rbsClose
          raise newException(ProtocolError, 
                             "received length doesn't match expected length, wanted " &
                             $length & " got " & $len(result.data))
    else:
      if getOrDefault(res.headers, "Connection") == "close":
        var buf = ""
        while true:
          buf = await recv(client.socket, BufferSize)
          if buf == "": 
            break
          add(result.data, buf)
        result.status = rbsClose

proc recvFullbody*(client: AsyncHttpClient, res: Response): Future[string] {.async.} = 
  result = ""
  while true:
    let (status, data) = await recvBody(client, res)
    if data != "":
      add(result, data)
    case status:
    of rbsClose:
      close(client)
      break
    of rbsEnd:
      break
    of rbsData:
      discard

proc recvFullbody*(client: AsyncHttpClient, res: Response, cb: Callback) {.async.} = 
  while true:
    let (status, data) = await recvBody(client, res)
    if data != "" and await cb(data):
      close(client)
      break
    case status:
    of rbsClose:
      close(client)
      break
    of rbsEnd:
      break
    of rbsData:
      discard

proc request*(client: AsyncHttpClient, httpMethod: string, httpUri: Uri, 
              headers: StringTableRef = nil, body: string = nil): 
             Future[tuple[res: Response, body: string]] {.async.} =
  await newConnection(client, httpUri)
  await sendHeaders(client, httpMethod, httpUri, headers)
  await sendBody(client, body)
  result.res = await recvHeaders(client)
  if result.res.statusCode == 100:
    result.res = await recvHeaders(client)
  if result.res.statusCode == 417:
    raise newException(RequestError, "expectation failed")
  result.body = await recvFullbody(client, result.res)

proc request*(client: AsyncHttpClient, httpMethod: HttpMethod, httpUri: Uri, 
              headers: StringTableRef = nil, body: string = nil): 
             Future[tuple[res: Response, body: string]] =
  request(client, substr($httpMethod, len("http")), httpUri, headers, body)

when isMainModule:
  proc main() {.async.} =
    var client = newAsyncHttpClient()
    let (res1, body1) = await request(client, httpGET, parseUri("http://www.baidu.com"), 
                                      newStringTable(modeCaseInsensitive))
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res1.statusCode
    echo "Got response reason phrase: ", res1.reasonPhrase
    echo "Got response headers: ", res1.headers
    echo "Got response body: ", body1

    let (res2, body2) = await request(client, "GET", parseUri("http://www.baidu.com"))
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res2.statusCode
    echo "Got response reason phrase: ", res2.reasonPhrase
    echo "Got response headers: ", res2.headers
    echo "Got response body: ", body2

    let (res3, body3) = await request(client, "GET", parseUri("https://github.com/"), 
                                      newStringTable(modeCaseInsensitive))
    echo "Client connected: ", client.connected
    echo "Got response status code: ", res3.statusCode
    echo "Got response reason phrase: ", res3.reasonPhrase
    echo "Got response headers: ", res3.headers
    echo "Got response body: ", body3

  waitFor main()
