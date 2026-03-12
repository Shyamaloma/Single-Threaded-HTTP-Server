#include "listener_socket.h"
#include "iowrapper.h"
#include "debug.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define GET_PATTERN "^([a-zA-Z]{1,8}) (/[a-zA-Z0-9.-]{1,63}) (HTTP/[0-9]\\.[0-9])\r\n"

void invalidCommand(void) {
    fprintf(stderr, "Invalid Command\n");
}

void error_bad_request(int connfd) {
    char error[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n";
    write_n_bytes(connfd, error, sizeof(error) - 1);
    close(connfd);
    return;
}

void error_internal(int connfd) {
    char error[]
        = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal Server Error\n";
    write_n_bytes(connfd, error, sizeof(error) - 1);
    close(connfd);
    return;
}

void error_not_found(int connfd) {
    char error[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";
    write_n_bytes(connfd, error, sizeof(error) - 1);
    close(connfd);
    return;
}

void error_forbidden(int connfd) {
    char error[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n";
    write_n_bytes(connfd, error, sizeof(error) - 1);
    close(connfd);
    return;
}

void write_func(size_t initial_read, size_t header_len, size_t remaining, int w_fd, int connfd,
    char buf[BUFFER_SIZE]) {
    if (initial_read > header_len) {
        size_t buffered_data_len = initial_read - header_len;
        size_t to_write = (buffered_data_len < remaining) ? buffered_data_len : remaining;

        char *p = buf + header_len;
        size_t bytes_left = to_write;

        while (bytes_left > 0) {
            ssize_t bytes_written = write_n_bytes(w_fd, p, bytes_left);

            if (bytes_written < 0) {
                return;
            }

            p += bytes_written;
            bytes_left -= bytes_written;
        }
        remaining -= to_write;
    }

    char file_buf[BUFFER_SIZE];
    while (remaining > 0) {
        ssize_t to_read = 0;
        if (remaining < sizeof(file_buf)) {
            to_read = remaining;
        } else {
            to_read = sizeof(file_buf);
        }

        ssize_t bytes_read = read(connfd, file_buf, to_read);

        if (bytes_read < 0) {
            error_internal(connfd);
            return;
        }

        if (bytes_read == 0)
            error_bad_request(connfd);

        char *p = file_buf;
        ssize_t bytes_to_write = bytes_read;

        while (bytes_to_write > 0) {
            ssize_t bytes_written = write_n_bytes(w_fd, p, bytes_to_write);

            if (bytes_written < 0) {
                return;
            }

            p += bytes_written;
            bytes_to_write -= bytes_written;
        }

        remaining -= bytes_read;
    }
}

void get_logic(char buf[BUFFER_SIZE], regmatch_t pmatch[], int connfd) {
    buf[pmatch[2].rm_eo] = '\0';
    char *uri = buf + (1 + pmatch[2].rm_so);
    int read_fd = open(uri, O_RDONLY, 0);

    struct stat st;

    if (stat(uri, &st) == -1) {
        if (errno == ENOENT) {
            error_not_found(connfd);
        } else if (errno == EACCES || errno == EISDIR || errno == ENOTDIR) {
            error_forbidden(connfd);
        }
    }

    if (!S_ISREG(st.st_mode)) {
        error_forbidden(connfd);
    }

    char ok_status[128];
    int len = snprintf(
        ok_status, sizeof(ok_status), "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", st.st_size);
    write_n_bytes(connfd, ok_status, len);

    char file_buffer[4096];
    while (1) {

        ssize_t read_res = read_n_bytes(read_fd, file_buffer, sizeof(file_buffer));

        if (read_res < 0) {
            close(connfd);
            return;
        }

        if (read_res == 0) {
            break;
        }

        char *p = file_buffer;
        ssize_t bytes_to_write = read_res;

        while (bytes_to_write > 0) {
            ssize_t w_res = write_n_bytes(connfd, p, bytes_to_write);
            if (w_res < 0) {
                close(connfd);
                return;
            }

            p += w_res;
            bytes_to_write -= w_res;
        }
    }

    close(read_fd);
    close(connfd);
    return;
}

void put_logic(char buf[BUFFER_SIZE], regmatch_t pmatch[], int connfd, int initial_read) {
    char *cl = strstr(buf, "Content-Length:");

    if (cl == NULL) {
        error_bad_request(connfd);
        return;
    }

    cl += strlen("Content-Length:");
    while (*cl == ' ') {
        cl++;
    }

    char *end;
    long bytes_to_write_l = strtol(cl, &end, 10);
    if (bytes_to_write_l < 0)
        error_bad_request(connfd);
    size_t bytes_to_write = (size_t) bytes_to_write_l;

    if (bytes_to_write == 0) {
        error_bad_request(connfd);
        return;
    }

    buf[pmatch[2].rm_eo] = '\0';

    char *uri = buf + (1 + pmatch[2].rm_so);
    struct stat st;
    bool existed = (stat(uri, &st) == 0);

    if (existed) {
        if (!S_ISREG(st.st_mode)) {
            error_forbidden(connfd);
        }
    }

    int write_fd = open(uri, O_WRONLY | O_CREAT | O_TRUNC, 0664);

    if (write_fd == -1) {
        if (errno == EACCES || errno == EISDIR) {
            error_forbidden(connfd);
            return;
        } else {
            error_internal(connfd);
            return;
        }
    }

    char *hdr_end = NULL;

    for (int i = 0; i <= initial_read - 4; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            hdr_end = buf + i;
            break;
        }
    }

    if (hdr_end == NULL) {
        close(write_fd);
        error_bad_request(connfd);
        return;
    }

    ssize_t header_len = (hdr_end - buf) + 4;
    ssize_t remaining = bytes_to_write;

    write_func(initial_read, header_len, remaining, write_fd, connfd, buf);
    close(write_fd);

    if (!existed) {
        char response[] = "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n";
        write_n_bytes(connfd, response, strlen(response));
    } else {
        char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n";
        write_n_bytes(connfd, response, strlen(response));
    }

    close(connfd);
    return;
}

void parse_through(char buf[BUFFER_SIZE], int connfd, int intial_read) {

    regex_t re;
    regmatch_t pmatch[4];
    regcomp(&re, GET_PATTERN, REG_EXTENDED);
    int reg_res = regexec(&re, buf, 4, pmatch, 0);

    if (reg_res != 0) {
        char error[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n";
        write_n_bytes(connfd, error, sizeof(error) - 1);
        close(connfd);
        regfree(&re);
        return;
    }

    size_t version_len = pmatch[3].rm_eo - pmatch[3].rm_so;

    if (version_len != 8 || strncmp(buf + pmatch[3].rm_so, "HTTP/1.1", 8) != 0) {
        char error[] = "HTTP/1.1 505 Version Not Supported\r\nContent-Length: 22\r\n\r\nVersion "
                       "Not Supported\n";
        write_n_bytes(connfd, error, sizeof(error) - 1);
        close(connfd);
        regfree(&re);
        return;
    }

    ssize_t input_len = pmatch[1].rm_eo - pmatch[1].rm_so;
    if (input_len == 3 && strncmp(buf + pmatch[1].rm_so, "PUT", 3) == 0) {
        put_logic(buf, pmatch, connfd, intial_read);
    } else if (input_len == 3 && strncmp(buf + pmatch[1].rm_so, "GET", 3) == 0) {
        get_logic(buf, pmatch, connfd);
    } else {
        char error[]
            = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 16\r\n\r\nNot Implemented\n";
        write_n_bytes(connfd, error, sizeof(error) - 1);
        close(connfd);
        regfree(&re);
        return;
    }

    regfree(&re);
    return;
}

void handle_connection(int connfd) {
    char buffy[BUFFER_SIZE];

    // Initial Read for further parsing
    int total = 0;
    while (1) {
        ssize_t r_res = read(connfd, buffy + total, sizeof(buffy) - total - 1);

        if (r_res < 0)
            error_bad_request(connfd);

        if (r_res == 0)
            break;

        total += r_res;
        buffy[total] = '\0';

        if (strstr(buffy, "\r\n\r\n") != NULL) {
            break;
        } else {
            error_bad_request(connfd);
            return;
        }
    }
    parse_through(buffy, connfd, total);
    return;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Invalid Input\n");
        exit(1);
    }

    // ---------- Listen for incoming connections ----------

    int port_num = atoi(argv[1]);

    if (port_num < 1 || port_num > 65535) {
        fprintf(stderr, "Invalid Port\n");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    Listener_Socket_t *socket = ls_new(port_num);

    if (socket == NULL) {
        fprintf(stderr, "Invalid Port\n");
        exit(1);
    }

    // Loop forever
    while (1) {
        // Accept a new client connection
        int connection_socket = ls_accept(socket);
        handle_connection(connection_socket);
    }

    return 0;
}
