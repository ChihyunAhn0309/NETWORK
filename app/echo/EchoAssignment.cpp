#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.
  int success;
  char buf[1024];
  char client_ipcopy[16];
  // bind_ip is just for the listening.
  struct sockaddr_in listen_addr, client_addr;
  socklen_t sock_len = sizeof(struct sockaddr);
  memset(&listen_addr, 0, sizeof(struct sockaddr_in));
  memset(&client_addr, 0, sizeof(struct sockaddr_in));
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(port);

  if(inet_pton(AF_INET, bind_ip, &listen_addr.sin_addr) < 0){
    return -1;
  }
  int listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(listen_socket == -1){
    return -1;
  }
  if(bind(listen_socket, (struct sockaddr*)&listen_addr, sizeof(struct sockaddr)) < 0){
    return -1;
  }
  if(listen(listen_socket, 50) < 0){
    return -1;
  }
  while(true){
    int client_fd = accept(listen_socket, (struct sockaddr*)&client_addr, &sock_len);
    if(client_fd == -1){
      return -1;
    }
    ssize_t read_byte = read(client_fd, buf, sizeof(buf));
    if(read_byte < 0){
      return -1;
    }
    buf[read_byte] = '\0';
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ipcopy, sizeof(client_ipcopy));
    ssize_t write_byte;
    if(strncmp(buf, "hello", 5) == 0){
      submitAnswer(client_ipcopy, buf);
      if(write(client_fd, server_hello, strlen(server_hello)) < 0){
        return -1;
      }
    }
    else if(strncmp(buf, "whoami", 6) == 0){
      submitAnswer(client_ipcopy, buf);
      if(write(client_fd, client_ipcopy, strlen(client_ipcopy)) < 0){
        return -1;
      }
    }
    else if(strncmp(buf, "whoru", 5) == 0){
      submitAnswer(client_ipcopy, buf);
      if(write(client_fd, "whoru", strlen("whoru")) < 0){
        return -1;
      }
    }
    else{
      submitAnswer(client_ipcopy, buf);
      if(write(client_fd, buf, strlen(buf)) < 0){
        return -1;
      };
    }
    if(close(client_fd) < 0){
      return -1;
    }
  }
  if(close(listen_socket) < 0){
    return -1;
  }
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.
  char buf[1024];
  int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(client_socket == -1){
    return -1;
  }
  int success;
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if(inet_pton(AF_INET, server_ip, &server_addr.sin_addr) < 0){
    return -1;
  }
  if(connect(client_socket, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) < 0){
    return -1;
  }
  if(write(client_socket, command, strlen(command)) < 0){
    return -1;
  }
  ssize_t read_byte = read(client_socket, buf, sizeof(buf));
  if(read_byte < 0){
    return -1;
  }
  buf[read_byte] = '\0';
  if(strncmp(buf, "whoru", 5) == 0){
    submitAnswer(server_ip, server_ip);
  }
  else{
    submitAnswer(server_ip, buf);
  }
  if(close(client_socket) < 0){
    return -1;
  }
  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
