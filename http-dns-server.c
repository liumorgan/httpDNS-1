#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#define MAX_FD 1024
#define DNS_REQUEST_SIZE 512
#define BUFF_SIZE 1024

typedef struct dns_request {
    char dns_req[DNS_REQUEST_SIZE + 1];
    char *http_rsp;
    unsigned int http_rsp_len, sent_len, dns_req_len;
    int fd;
    
} dns_t;
struct dns_hosts {
    char *host;
    char *ip;
    struct dns_hosts *next;
};

char errMsg[] = "HTTP/1.0 404 Not Found\r\nVia: Mmmdbybyd(HTTP-DNS Server)\r\nContent-type: charset=utf-8\r\n\r\n<html><head><title>HTTP DNS Server</title></head><body>查询域名失败<br/><br/>By: 萌萌萌得不要不要哒</body></html>";
char success_header[] = "HTTP/1.0 200 OK\r\nVia: Mmmdbybyd(HTTP-DNS Server)\r\n\r\n";
dns_t dns_list[MAX_FD - 2];
struct epoll_event evs[MAX_FD - 1], ev;
/* hosts变量 */
char *hosts_path = NULL;
FILE *hostsfp = NULL;
struct dns_hosts *hosts, *last_hosts = NULL;
int listenFd, dstFd, eFd;
socklen_t addr_len;

void usage(int code)
{
    fputs("http dns server(v0.1):\n"
    "    -l [listen_ip:]listen_port  \033[35G default listen_ip is 0.0.0.0\n"
    "    -u upper_ip[:upper_port]  \033[35G default upper is 114.114.114.114:53\n"
    "    -H hosts file path  \033[35G default none\n"
    "    -h \033[35G display this information\n", code ? stderr : stdout);
    exit(code);
}

int8_t read_hosts_file(char *path)
{
    char *ip_begin, *ip_end, *host_begin, *host_end, *buff, *next_line;
    int file_size, i;
    
    hosts = last_hosts = NULL;
    if ((hostsfp = fopen(path, "r")) == NULL)
    {
        fputs("error hosts file path", stderr);
        return 1;
    }

    //读取文件内容
    fseek(hostsfp, 0, SEEK_END);
    file_size = ftell(hostsfp);
    //文件没有内容则不用读取
    if (file_size == 0)
        return 0;
    if ((buff = (char *)alloca(file_size+1)) == NULL)
    {
        fclose(hostsfp);
        fputs("out of memory", stderr);
        return 1;
    }
    rewind(hostsfp);
    fread(buff, file_size, 1, hostsfp);
    *(buff + file_size) = '\0';
    fclose(hostsfp);
    
    struct dns_hosts *h = NULL;
    for (ip_begin = buff; ip_begin; ip_begin = next_line)
    {
        next_line = strchr(ip_begin, '\n');
        if (next_line != NULL)
            *next_line++ = '\0';
        while (*ip_begin == '\t' || *ip_begin == ' ' || *ip_begin == '\r')
            if (*ip_begin++ == '\0')
                continue;
        for (i = 0, ip_end = ip_begin; *ip_end != ' ' && *ip_end != '\t' && *ip_end != '\r' && *ip_end != '\0'; ip_end++)
        {
            if (*ip_end == '.')
                i++;
            else if (*ip_end == '\0')
                continue;
        }
        if (i != 3)
            continue;
        for (host_begin = ip_end; *host_begin == '\t' || *host_begin == ' ' || *host_begin == '\r'; )
        {
            if (*host_begin++ == '\0')
                continue;
        }
        for (host_end = host_begin; *host_end != ' ' && *host_end != '\t' && *host_end != '\r' && *host_end != '\n' && *host_end != '\0'; host_end++);
        if (h)
        {
            h->next = (struct dns_hosts *)malloc(sizeof(struct dns_hosts));
            if (h->next == NULL)
                return 1;
            h = h->next;
        }
        else
        {
            hosts = h = (struct dns_hosts *)malloc(sizeof(struct dns_hosts));
            if (hosts == NULL)
            {
                fputs("out of memory", stderr);
                return 1;
            }
        }
        h->next = NULL;
        h->ip = strndup(ip_begin, ip_end - ip_begin);
        if (*(host_end - 1) == '.')
            host_end--;
        h->host = strndup(host_begin, host_end - host_begin);
        if (h->ip == NULL || h->host == NULL)
        {
            fputs("out of memory", stderr);
            return 1;
        }
        
    }
    
    last_hosts = h;
    return 0;
}

inline char *hosts_lookup(char *host)
{
    struct dns_hosts *h;
    
    h = hosts;
    while (h)
    {
        if (strcmp(h->host, host) == 0)
            return h->ip;
        h = h->next;
    }

    return NULL;
}

inline void close_client(dns_t *dns)
{
    close(dns->fd);
    free(dns->http_rsp);
    dns->http_rsp = NULL;
    dns->sent_len = dns->dns_req_len = 0;
    dns->fd = -1;
}

inline void build_http_rsp(dns_t *dns, char *ips)
{
    dns->http_rsp_len = sizeof(success_header) + strlen(ips) - 1;
    dns->http_rsp = (char *)malloc(dns->http_rsp_len + 1);
    if (dns->http_rsp == NULL)
        return;
    strcpy(dns->http_rsp, success_header);
    strcpy(dns->http_rsp + sizeof(success_header) - 1, ips);
    dns->sent_len = 0;
}

inline void response_client(dns_t *out)
{
    int write_len = write(out->fd, out->http_rsp + out->sent_len, out->http_rsp_len - out->sent_len);
    if (write_len == out->http_rsp_len - out->sent_len || write_len == -1)
    {
        if (out->http_rsp == errMsg)
            out->http_rsp = NULL;
        close_client(out);
    }
    else
        out->sent_len += write_len;
}

inline void build_dns_req(dns_t *dns, char *domain, int domain_size)
{
    char *p, *_p;

    p = dns->dns_req + 12;
    memcpy(p+1, domain, domain_size + 1); //copy '\0'
    while ((_p = strchr(p+1, '.')) != NULL)
    {
        *p = _p - p - 1;
        p = _p;
    }
    *p = strlen(p+1);
    p = dns->dns_req + 14 + domain_size;
    *p++ = 0;
    *p++ = 1;
    *p++ = 0;
    *p++ = 1;
    dns->dns_req_len = p - dns->dns_req;
}

inline int8_t send_dns_req(char *dns_req, int req_len)
{
    int write_len = write(dstFd, dns_req, req_len);
    if (write_len == req_len)
        return 0;
    else if (write_len >= 0)
        return write_len;
    else
        return -1;
}

void query_dns()
{
    dns_t *dns;
    int i, ret;
    
    for (i = MAX_FD - 2, dns = &dns_list[MAX_FD - 3]; i--; dns--)
    {
        if (dns->http_rsp == NULL && dns->dns_req_len != dns->sent_len)
        {
            ret = send_dns_req(dns->dns_req + dns->sent_len, dns->dns_req_len - dns->sent_len);
            if (ret == 0)
            {
                dns->sent_len = dns->dns_req_len;
            }
            else if (ret > -1)
            {
                dns->sent_len += ret;
                return;
            }
            else
            {
                close_client(dns);
                break;
            }
        }
    }
    ev.events = EPOLLIN|EPOLLET;
    ev.data.fd = dstFd;
    epoll_ctl(eFd, EPOLL_CTL_MOD, dstFd, &ev);
}
    
void accept_dns_rsp()
{
    static char rsp_data[BUFF_SIZE + 1], *p, *ips;
    unsigned char *_p;
    dns_t *dns;
    int len, ips_len;

    while ((len = read(dstFd, rsp_data, BUFF_SIZE)) > 1)
    {
        if (*(int16_t *)rsp_data > MAX_FD - 3)
            continue;
        dns = &dns_list[*(int16_t *)rsp_data];
        dns->sent_len = 0;
        if (dns->dns_req_len + 12 > len)
        {
            dns->http_rsp = errMsg;
            dns->http_rsp_len = sizeof(errMsg);
            goto modEvToOut;
        }
        if ((unsigned char)rsp_data[3] != 128) //char只有7位可用，则正数最高为127
        {
            dns->http_rsp = errMsg;
            dns->http_rsp_len = sizeof(errMsg);
            goto modEvToOut;
        }
        rsp_data[len] = '\0';
        /* get ips */
        p = rsp_data + dns->dns_req_len + 11;
        ips_len = 0;
        ips = NULL;
        while (p - rsp_data + 4 <= len)
        {
            //type
            if (*(p - 8) != 1)
            {
                p += *p + 12;
                continue;
            }
            ips = (char *)realloc(ips, ips_len + 16);
            if (ips == NULL)
                break;
            _p = (unsigned char *)p + 1;
            ips_len += sprintf(ips + ips_len, "%d.%d.%d.%d", _p[0], _p[1], _p[2], _p[3]);
            p += 16; //next address
            ips[ips_len++] = ';';
        }
        if (ips)
        {
            ips[ips_len - 1] = '\0';
            //printf("ips %s\n", ips);
            build_http_rsp(dns, ips);
            free(ips);
            if (dns->http_rsp)
            {
                response_client(dns);
                if (dns->http_rsp == NULL)
                    continue;
            }
            else
            {
                dns->http_rsp = errMsg;
                dns->http_rsp_len = sizeof(errMsg);
            }
        }
        else
        {
            dns->http_rsp = errMsg;
            dns->http_rsp_len = sizeof(errMsg);
        }
        modEvToOut:
        ev.data.ptr = dns;
        ev.events = EPOLLOUT|EPOLLET;
        epoll_ctl(eFd, EPOLL_CTL_MOD, dns->fd, &ev);
    }
    
}

void read_client(dns_t *in) {
    static char  httpReq[BUFF_SIZE+1];
    int domain_size, httpReq_len;
    char *domain_begin, *domain_end, *domain = NULL, *ips;

    httpReq_len = read(in->fd, httpReq, BUFF_SIZE);
    //必须大于5，否则不处理
    if (httpReq_len < 6)
    {
        close_client(in);
        return;
    }
    httpReq[httpReq_len] = '\0';

    if ((domain_begin = strstr(httpReq, "?dn=")))
        domain_begin += 4;
    else if ((domain_begin = strstr(httpReq, "?host=")))
        domain_begin += 6;
    else
    {
        in->http_rsp = errMsg;
        in->http_rsp_len = sizeof(errMsg);
        goto response_client;
    }

    domain_end = strchr(domain_begin, ' ');
    if (domain_end == NULL)
    {
        in->http_rsp = errMsg;
        in->http_rsp_len = sizeof(errMsg);
        goto response_client;
    }
    if (*(domain_end - 1) == '.')
        domain_size = domain_end - domain_begin - 1;
    else
        domain_size = domain_end - domain_begin;
    domain = strndup(domain_begin, domain_size);
    if (domain == NULL || domain_size <= 0)
    {
        in->http_rsp = errMsg;
        in->http_rsp_len = sizeof(errMsg);
        goto response_client;
    }
    if (hostsfp && (ips = hosts_lookup(domain)) != NULL)
    {
        free(domain);
        build_http_rsp(in, ips);
        if (in->http_rsp == NULL)
        {
            in->http_rsp = errMsg;
            in->http_rsp_len = sizeof(errMsg);
        }
    }
    else
    {
        build_dns_req(in, domain, domain_size);
        free(domain);
        int ret = send_dns_req(in->dns_req, in->dns_req_len);
        switch (ret)
        {
            case 0:
                in->sent_len = in->dns_req_len;
                ev.events = EPOLLIN;
            break;
            
            case -1:
                close_client(in);
            return;
            
            default:
                in->sent_len += ret;
                ev.events = EPOLLIN|EPOLLOUT;
            break;
        }
        ev.data.fd = dstFd;
        epoll_ctl(eFd, EPOLL_CTL_MOD, dstFd, &ev);
        return;
    }

    response_client:
    response_client(in);
    if (in->http_rsp)
    {
        ev.data.ptr = in;
        ev.events = EPOLLOUT|EPOLLET;
        epoll_ctl(eFd, EPOLL_CTL_MOD, in->fd, &ev);
    }
}

void accept_client()
{
    struct sockaddr_in addr;
    dns_t *client;
    int i;
    
    for (i = MAX_FD - 2; i--;)
    {
        if (dns_list[i].fd < 0)
        {
            client = &dns_list[i];
            break;
        }
    }
    //printf("i = %d\n" , i);
    if (i < 0)
        return;
    client->fd = accept(listenFd, (struct sockaddr *)&addr, &addr_len);
    if (client->fd < 0)
    {
        return;
    }
    fcntl(client->fd, F_SETFL, O_NONBLOCK);
    ev.data.ptr = client;
    ev.events = EPOLLIN|EPOLLET;
    if (epoll_ctl(eFd, EPOLL_CTL_ADD, client->fd, &ev) != 0)
    {
        close(client->fd);
        client->fd = -1;
        return;
    }
}

void start_server()
{
    int n;
    
    while (1)
    {
        n = epoll_wait(eFd, evs, MAX_FD - 1, -1);
        //printf("n = %d\n", n);
        while (n-- > 0)
        {
            if (evs[n].data.fd == listenFd)
            {
            //puts("1");
                accept_client();
            //puts("2");
            }
            else if (evs[n].data.fd == dstFd)
            {
                if (evs[n].events & EPOLLIN)
                {
            //puts("3");
                    accept_dns_rsp();
            //puts("4");
                }
                else if (evs[n].events & EPOLLOUT)
                {
            //puts("5");
                    query_dns();
            //puts("6");
                }
            }
            else if (evs[n].events & EPOLLIN)
            {
            //puts("7");
                read_client(evs[n].data.ptr);
            //puts("8");
            }
            else if (evs[n].events & EPOLLOUT)
            {
            //puts("9");
                response_client(evs[n].data.ptr);
            //puts("10");
            }
        }
    }
}

int initialize(int argc, char *argv[])
{
    struct sockaddr_in addr;
    char *p;
    int opt, optval = 0;
    
    //PIPE
    signal(SIGPIPE, SIG_IGN);
    addr.sin_family = AF_INET;
    addr_len = sizeof(addr);
    dstFd = socket(AF_INET, SOCK_DGRAM, 0);
    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (dstFd < 0 || listenFd < 0)
    {
        perror("socket");
        return 1;
    }
    fcntl(dstFd, F_SETFL, O_NONBLOCK);
    fcntl(listenFd, F_SETFL, O_NONBLOCK);
    while ((opt = getopt(argc, argv, ":l:H:u:h")) != -1)
    {
        switch(opt)
        {
            case 'l':
                if ((p = strchr(optarg, ':')) != NULL)
                {
                    *p = '\0';
                    addr.sin_addr.s_addr = inet_addr(optarg);
                    addr.sin_port = htons(atoi(p+1));
                }
                else
                {
                    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
                    addr.sin_port = htons(atoi(optarg));
                }
                optval = 1;
                if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0)
                {
                    perror("setsockopt");
                    return 1;
                }
                if (bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
                {
                    perror("bind");
                    return 1;
                }
                if (listen(listenFd, 20) != 0)
                {
                    perror("listen");
                    return 1;
                }
            break;

            case 'H':
                if (read_hosts_file(optarg) != 0)
                    return 1;
            break;

            case 'u':
                if ((p = strchr(optarg, ':')) != NULL)
                {
                    *p = 0;
                    addr.sin_addr.s_addr = inet_addr(optarg);
                    addr.sin_port = htons(atoi(p+1));
                }
                else
                {
                    addr.sin_addr.s_addr = inet_addr(optarg);
                    addr.sin_port = htons(53);
                }
                connect(dstFd, (struct sockaddr *)&addr, sizeof(addr));
            break;
            
            case 'h':
                usage(0);
            
            default:
                usage(1);
        }
    }
    if (optval == 0)
    {
        usage(1);
    }
    eFd = epoll_create(MAX_FD - 1);
    if (eFd < 0)
    {
        perror("epoll_create");
        return 1;
    }
    ev.data.fd = listenFd;
    ev.events = EPOLLIN;
    epoll_ctl(eFd, EPOLL_CTL_ADD, listenFd, &ev);
    ev.data.fd = dstFd;
    epoll_ctl(eFd, EPOLL_CTL_ADD, dstFd, &ev);
    memset(dns_list, 0, sizeof(dns_list));
    //初始化DNS请求结构
    int16_t i;
    for (i = MAX_FD - 2; i--; )
    {
        dns_list[i].fd = -1;
        memcpy(dns_list[i].dns_req, &i, sizeof(i));
        dns_list[i].dns_req[2] = 1;
        dns_list[i].dns_req[3] = 0;
        dns_list[i].dns_req[4] = 0;
        dns_list[i].dns_req[5] = 1;
        dns_list[i].dns_req[6] = 0;
        dns_list[i].dns_req[7] = 0;
        dns_list[i].dns_req[8] = 0;
        dns_list[i].dns_req[9] = 0;
        dns_list[i].dns_req[10] = 0;
        dns_list[i].dns_req[11] = 0;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    
    if (initialize(argc, argv) != 0)
        return 1;
    if (daemon(1, 1) != 0)
    {
        perror("daemon");
        return 1;
    }
    start_server();
    
    return 0;
} 
