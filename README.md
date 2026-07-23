# Single-Threaded HTTP/1.1 Server

## Overview

This project is a **single-threaded HTTP/1.1 server implemented in C** that handles basic client requests over TCP sockets. The server supports **GET** and **PUT** methods, allowing clients to retrieve files from the server or upload files to it.

The server is designed to demonstrate low-level systems programming concepts including:

* Socket programming
* File I/O
* HTTP protocol parsing
* Error handling
* Regex-based request validation

---

## Features

* ✅ Supports **HTTP/1.1 GET** requests (retrieve files)
* ✅ Supports **HTTP/1.1 PUT** requests (upload/create files)
* ✅ Handles common HTTP errors:

  * `400 Bad Request`
  * `403 Forbidden`
  * `404 Not Found`
  * `500 Internal Server Error`
  * `501 Not Implemented`
  * `505 Version Not Supported`
* ✅ Uses **POSIX system calls** (`read`, `write`, `open`, `stat`)
* ✅ Validates requests using **regular expressions**
* ✅ Efficient buffered I/O using custom wrapper functions
* ✅ Prevents crashes from broken pipes (`SIGPIPE` ignored)

---

## Architecture

### Server Flow

1. **Socket Initialization**

   * Server listens on a user-specified port.
   * Uses a listener socket abstraction (`listener_socket.h`).

2. **Connection Handling**

   * Accepts incoming client connections in a loop.
   * Each connection is handled **sequentially** (single-threaded).

3. **Request Parsing**

   * Reads incoming data into a buffer.
   * Detects end of HTTP headers (`\r\n\r\n`).
   * Uses regex to validate request format:

     ```
     METHOD /filename HTTP/1.1
     ```

4. **Request Dispatch**

   * Routes request to:

     * `get_logic()` for GET
     * `put_logic()` for PUT

---

## Supported HTTP Methods

### GET

* Retrieves a file from the server.
* Returns:

  * `200 OK` with file contents
  * `404 Not Found` if file does not exist
  * `403 Forbidden` if access is denied or not a regular file

### PUT

* Uploads or overwrites a file on the server.
* Requires `Content-Length` header.
* Returns:

  * `201 Created` if file is newly created
  * `200 OK` if file is overwritten

---

## Error Handling

The server explicitly handles multiple HTTP error cases:

| Error Code | Description                            |
| ---------- | -------------------------------------- |
| 400        | Malformed request or missing headers   |
| 403        | Permission denied or invalid file type |
| 404        | File not found                         |
| 500        | Internal server failure                |
| 501        | Unsupported HTTP method                |
| 505        | HTTP version not supported             |

---

## Key Implementation Details

### Regex-Based Parsing

Requests are validated using:

```
^([a-zA-Z]{1,8}) (/[a-zA-Z0-9.-]{1,63}) (HTTP/[0-9]\.[0-9])\r\n
```

This ensures strict adherence to HTTP formatting.

---

### Buffered File Transfer

* Uses a fixed buffer size (`4096 bytes`)
* Handles partial reads/writes safely
* Ensures full transmission using `write_n_bytes`

---

### PUT Request Handling

* Extracts `Content-Length`
* Handles:

  * Partial body reads from initial buffer
  * Remaining bytes streamed from socket
* Writes data incrementally to file

---

### File Validation

* Uses `stat()` to:

  * Check file existence
  * Ensure file is a **regular file**
  * Prevent directory access

---

## Build Instructions

### Requirements

* GCC compiler
* POSIX-compatible system (Linux/macOS)

### Compile

```bash
gcc -o httpserver server.c listener_socket.c iowrapper.c -Wall -Wextra -Werror
```

---

## Usage

```bash
./httpserver <port>
```

Example:

```bash
./httpserver 8080
```

---

## Testing

### GET Request

```bash
curl http://localhost:8080/file.txt
```

### PUT Request

```bash
curl -X PUT -d "Hello World" http://localhost:8080/file.txt
```

---

## Limitations

* Single-threaded (handles one client at a time)
* Only supports GET and PUT
* No persistent connections (no keep-alive)
* Limited header parsing (only `Content-Length` used)
* No MIME type handling

---

## Future Improvements

* Multi-threading or thread pool support
* HTTP/1.1 persistent connections
* Support for additional methods (POST, DELETE)
* Improved header parsing
* Logging and request tracing
* Security improvements (path sanitization)

---

## What I Learned

Through this project, I developed a strong understanding of:

* How HTTP works at a low level
* TCP socket communication
* Efficient file I/O handling in C
* Parsing structured protocols safely
* Designing robust error handling in systems software

---

## Author

**Shyam Kishan**
Computer Engineering @ UC Santa Cruz