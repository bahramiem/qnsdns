// minimal_spcdns_libuv.c
#include <stdio.h>
#include <string.h>

#include "third_party/uv.h"
#include "third_party/SPCDNS/dns.h"
#include "third_party/SPCDNS/output.h"

#include <stdlib.h>

typedef struct {
    uv_udp_t udp;
    uv_udp_send_t send_req;
    struct sockaddr_in dest;
    char recvbuf[DNS_BUFFER_UDP];
    dns_packet_t sendbuf[DNS_BUFFER_UDP];
    char domain[256];
} async_dns_req_t;

static void on_close(uv_handle_t* handle) {
    async_dns_req_t *req = handle->data;
    free(req);
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)suggested_size;
    async_dns_req_t *req = handle->data;
    buf->base = req->recvbuf;
    buf->len  = sizeof(req->recvbuf);
}

static void recv_cb(uv_udp_t *handle,
                    ssize_t nread,
                    const uv_buf_t *buf,
                    const struct sockaddr *addr,
                    unsigned flags)
{
    (void)addr;
    (void)flags;

    if (nread <= 0) {
        if (!uv_is_closing((uv_handle_t*)handle)) {
            uv_close((uv_handle_t*)handle, on_close);
        }
        return;
    }

    async_dns_req_t *req = handle->data;

    dns_decoded_t decoded[DNS_DECODEBUF_4K];
    size_t decodesize = sizeof(decoded);
    dns_rcode_t rc;

    rc = dns_decode(decoded,
                    &decodesize,
                    (const dns_packet_t *)buf->base,
                    (size_t)nread);

    if (rc != RCODE_OKAY) {
        fprintf(stderr, "dns_decode failed for %s: %d\n", req->domain, rc);
    } else {
        printf("\n--- Response for %s ---\n", req->domain);
        dns_print_result((dns_query_t *)decoded);
        printf("-----------------------------\n\n");
    }

    if (!uv_is_closing((uv_handle_t*)handle)) {
        uv_close((uv_handle_t*)handle, on_close);
    }
}

static void send_cb(uv_udp_send_t* send_req, int status) {
    if (status != 0) {
        fprintf(stderr, "Send error: %s\n", uv_strerror(status));
        if (!uv_is_closing((uv_handle_t*)send_req->handle)) {
            uv_close((uv_handle_t*)send_req->handle, on_close);
        }
    }
}

static void send_async_dns_query(uv_loop_t *loop, const char *domain, const char *server_ip) {
    async_dns_req_t *req = calloc(1, sizeof(async_dns_req_t));
    if (!req) {
        fprintf(stderr, "Out of memory\n");
        return;
    }

    strncpy(req->domain, domain, sizeof(req->domain) - 1);
    
    if (uv_udp_init(loop, &req->udp) != 0) {
        fprintf(stderr, "uv_udp_init failed\n");
        free(req);
        return;
    }

    req->udp.data = req;
    uv_ip4_addr(server_ip, 53, &req->dest);

    dns_question_t question;
    memset(&question, 0, sizeof(question));
    question.name  = req->domain;
    question.type  = RR_A;
    question.class = CLASS_IN;

    dns_query_t query;
    memset(&query, 0, sizeof(query));
    query.id = rand() & 0xFFFF;
    query.query = true;
    query.rd = true;
    query.qdcount = 1;
    query.questions = &question;

    size_t packetsize = sizeof(req->sendbuf);

    dns_rcode_t rc = dns_encode(req->sendbuf, &packetsize, &query);
    if (rc != RCODE_OKAY) {
        fprintf(stderr, "dns_encode failed for %s: %d\n", domain, rc);
        uv_close((uv_handle_t*)&req->udp, on_close);
        return;
    }

    if (uv_udp_recv_start(&req->udp, alloc_cb, recv_cb) != 0) {
        fprintf(stderr, "uv_udp_recv_start failed\n");
        uv_close((uv_handle_t*)&req->udp, on_close);
        return;
    }

    uv_buf_t buf = uv_buf_init((char *)req->sendbuf, (unsigned int)packetsize);
    if (uv_udp_send(&req->send_req,
                    &req->udp,
                    &buf,
                    1,
                    (const struct sockaddr *)&req->dest,
                    send_cb) != 0) {
        fprintf(stderr, "uv_udp_send failed\n");
        uv_close((uv_handle_t*)&req->udp, on_close);
        return;
    }
}

int main(void)
{
    uv_loop_t *loop = uv_default_loop();

    printf("Sending async consecutive queries...\n");
    send_async_dns_query(loop, "example.com.", "8.8.8.8");
    send_async_dns_query(loop, "google.com.", "8.8.4.4");
    send_async_dns_query(loop, "cloudflare.com.", "1.1.1.1");

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
