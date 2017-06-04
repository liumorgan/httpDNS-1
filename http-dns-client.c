#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <signal.h>

#define DNS_MAX_CONNECTION 128 //此值的大小关系到respod_clients函数的效率
#define DATA_SIZE 512
#define HTTP_RSP_SIZE 1024

typedef struct dns_connection {
    char dns_req[DATA_SIZE];
    struct sockaddr_in src_addr;
    char *reply; //回应内容
    char *http_request, *host;
    unsigned int http_request_len, dns_rsp_len;
    int fd;
    char query_type;
    unsigned host_len :7; //域名最大长度64位
    unsigned wait_response_client :1; //已构建好DNS回应，等待可写事件
} dns_t;
struct dns_cache {
    int question_len;
    char *question;
    char *answer;
    struct dns_cache *next;
};

dns_t dns_list[DNS_MAX_CONNECTION];
struct epoll_event evs[DNS_MAX_CONNECTION+1], ev;
char http_rsp[HTTP_RSP_SIZE + 1];
struct sockaddr_in dst_addr;
//当请求为IP查询域名类型时，返回固定的域名，不联网检查以节省资源，开头的0为域名字段的长度，启动时会自动修改该值
char PTR_domain[] = {0, 7, 'm', 'd', 'b', 'y', 'b', 'y', 'd', 3, 't', 'o', 'p', 0}, *cachePath = NULL, *host_value;
int dnsListenFd = -1, dns_efd;
unsigned int host_value_len;
/* 缓存变量 */
FILE *cfp = NULL;
struct dns_cache *cache, *cache_temp;
socklen_t addr_len = sizeof(dst_addr);
unsigned int cache_using, cacheLimit;

void help(int ret)
{
    puts("httpdns(v0.1):\n"
    "    -l [监听ip:]监听端口\n"
    "    -d 目标ip[:目标端口]\n"
    "    -c 缓存路径\n"
    "    -L 限制缓存数目\n"
    "    -H 设置Host\n"
    "    -h 显示这个信息\n");
    exit(ret);
}

/* 因为某些系统库的memcpy不能src + len > dst，这个函数正是为了解决这样的问题，但是效率低一点点 */
#ifdef XMEMCPY
typedef struct bit128 {
    char data[16];
} bit128_t;
typedef struct bit256 {
    char data[32];
} bit256_t;
void xmemcpy(char *src, const char *dst, size_t len)
{
    bit256_t *to256 = (bit256_t *)src, *from256 = (bit256_t *)dst;
    while (len >= sizeof(bit256_t))
    {
        *to256++ = *from256++;
        len -= sizeof(bit256_t);
    }
    if (len >= sizeof(bit128_t))
    {
        bit128_t *to128 = (bit128_t *)to256;
        *to128 = *(bit128_t *)from256;
        src = (char *)(to128 + 1);
        dst = (char *)((bit128_t *)from256 + 1);
        len -= sizeof(bit128_t);
    }
    else
    {
        src = (char *)to256;
        dst = (char *)from256;
    }
    /*
    if (len >= sizeof(int64_t))
    {
        int64_t *to64 = (int64_t *)src;
        *to64 = *(int64_t *)dst;
        src = (char *)(to64 + 1);
        dst += sizeof(int64_t);
        len -= sizeof(int64_t);
    }
    */
    while (len--)
        *src++ = *dst++;
}
#else
#define xmemcpy memcpy
#endif

int8_t read_cache_file()
{
    char *buff, *answer, *question;
    long file_size;

    cache = cache_temp = NULL;
    cache_using = 0;
    if ((cfp = fopen(cachePath, "rb+")) == NULL)
    {
        //保持文件打开状态，防止切换uid后权限不足导致无法写入文件
        if ((cfp = fopen(cachePath, "wb")) == NULL)
            return 1;
        else
            return 0;
    }

    //读取文件内容
    fseek(cfp, 0, SEEK_END);
    file_size = ftell(cfp);
    if ((buff = (char *)alloca(file_size)) == NULL)
    {
        fclose(cfp);
        return 1;
    }
    rewind(cfp);
    fread(buff, file_size, 1, cfp);

    //读取缓存，一组缓存的内容为[ipDomain\0]，其中ip占5字节
    for (answer = buff; answer - buff < file_size; answer = question + cache->question_len + 2)
    {
        cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
        if (cache_temp == NULL)
            return 1;
        cache_temp->next = cache;
        cache = cache_temp;
        cache_using++;
        cache->answer = strndup(answer, 5);
        question = answer + 5;
        cache->question = strdup(question);
        if (cache->question == NULL || cache->answer == NULL)
            return 1;
        cache->question_len = strlen(question) - 1;
    }
    /* 删除重复记录 */
    struct dns_cache *before, *after;
    for (; cache_temp; cache_temp = cache_temp->next)
    {
        for (before = cache_temp; before && (after = before->next) != NULL; before = before->next)
        {
            if (strcmp(after->question, cache_temp->question) == 0)
            {
                before->next = after->next;
                free(after->question);
                free(after->answer);
                free(after);
                cache_using--;
            }
        }
    }

    fclose(cfp);
    cfp = fopen(cachePath, "wb");
    return 0;
}

void write_dns_cache()
{
    while (cache)
    {
        fputs(cache->answer, cfp);
        fputs(cache->question, cfp);
        fputc('\0', cfp);
        cache = cache->next;
    }

    exit(0);
}


inline char *cache_lookup(char *question, dns_t *dns)
{
    struct dns_cache *c;

    for (c = cache; c; c = c->next)
    {
        if (strcmp(c->question, question) == 0)
        {
            dns->host_len = c->question_len;
            dns->query_type = 1;
            return c->answer;
        }
    }

    return NULL;
}

void cache_record(dns_t *dns)
{
    cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
    if (cache_temp == NULL)
        return;
    cache_temp->question = strdup(dns->dns_req + 12);
    if (cache_temp->question == NULL)
    {
        free(cache_temp);
        return;
    }
    cache_temp->next = cache;
    cache = cache_temp;
    cache->question_len = dns->host_len;
    cache->answer = dns->reply;
    if (cacheLimit)
    {
        //到达缓存记录条目限制则释放前一半缓存
        if (cache_using >= cacheLimit)
        {
            struct dns_cache *free_c;
            int i;
            for (i = cache_using = cacheLimit >> 1; i--; cache_temp = cache_temp->next);
            for (free_c = cache_temp->next, cache_temp->next = NULL; free_c; free_c = cache_temp)
            {
                cache_temp = free_c->next;
                free(free_c);
            }
        }
        cache_using++;
    }
}


inline int8_t respond_client(dns_t *dns)
{
    int write_len = sendto(dnsListenFd, dns->dns_req, dns->dns_rsp_len, 0, (struct sockaddr *)&dns->src_addr, sizeof(struct sockaddr_in));
    if (write_len == dns->dns_rsp_len)
    {
        dns->query_type = 0;
        return 0;
    }
    else if (write_len == -1)
        return -1;
    else
    {
        dns->dns_rsp_len -= write_len;
        xmemcpy(dns->dns_req, dns->dns_req + write_len, dns->dns_rsp_len);
        return 1;
    }
}

inline void respond_clients()
{
    int i;
    for (i = 0; i < DNS_MAX_CONNECTION; i++)
    {
        if (dns_list[i].wait_response_client)
        {
            if (respond_client(&dns_list[i]) == 1)
                return;
            else
                dns_list[i].wait_response_client = 0;
        }
    }
    ev.events = EPOLLIN;
    ev.data.fd = dnsListenFd;
    epoll_ctl(dns_efd, EPOLL_CTL_MOD, dnsListenFd, &ev);
}

/* 分析DNS请求 */
int8_t parse_dns_request(char *dns_req, dns_t *dns)
{
    dns_req += 13; //跳到域名部分
    dns->host_len = strlen(dns_req);
    //判断请求类型
    switch ((dns->query_type = *(dns_req + 2 + dns->host_len)))
    {
        case 28:    //查询ipv6地址
            dns->query_type = 1; //httpDNS不支持查询ipv6，所以改成ipv4
            
        case 1:    //查询ipv4地址
            dns->host = strdup(dns_req);
            if (dns->host == NULL)
                return 1;
            int len;
            for (len = *(--dns_req); dns_req[len+1] != 0; len += dns_req[len])
            {
                //防止数组越界
                if (len > dns->host_len)
                {
                    free(dns->host);
                    return 1;
                }
                dns->host[len++] = '.';
            }
            return 0;
            
        default:
            return 1;
    }
}

/* 建立DNS回应 */
int8_t build_dns_response(dns_t *dns)
{
    char *p;

    //18: 查询资源的前(12字节)后(6字节)部分
    if (dns->reply)
        dns->dns_rsp_len = 18 + dns->host_len + 12 + *dns->reply;
    else
        dns->dns_rsp_len = 18 + dns->host_len;
    if (dns->dns_rsp_len > DATA_SIZE)
    {
        dns->query_type = 0;
        return 1; //超出缓冲大小
    }
    /* 问题数 */
    dns->dns_req[4] = 0;
    dns->dns_req[5] = 1;
    /* 资源记录数 */
    dns->dns_req[6] = 0;
    dns->dns_req[7] = 0;
    /* 授权资源记录数 */
    dns->dns_req[8] = 0;
    dns->dns_req[9] = 0;
    /* 额外资源记录数 */
    dns->dns_req[10] = 0;
    dns->dns_req[11] = 0;    
    /* 如果有回应内容(资源记录) */
    if (dns->reply)
    {
        p = dns->dns_req + 18 + dns->host_len;
        /* 资源记录数+1 */
        dns->dns_req[7]++;
        /* 成功标志 */
        dns->dns_req[2] = (char)133;
        dns->dns_req[3] = (char)128;
        /* 指向主机域名 */
        p[0] = (char)192;
        p[1] = 12;
        /* 回应类型 */
        p[2] = 0;
        p[3] = dns->query_type;
        /* 区域类别 */
        p[4] = 0;
        p[5] = 1;
        /* 生存时间 (1 ora) */
        p[6] = 0;
        p[7] = 0;
        p[8] = 14;
        p[9] = 16;
        /* 回应长度 */
        p[10] = 0;
        //p[11] = 4;  //reply中包含回应长度
        strcpy(p+11, dns->reply);
    }
    else
    {
        /* 失败标志 */
        dns->dns_req[2] = (char)129;
        dns->dns_req[3] = (char)130;
    }
    if (respond_client(dns) == 1)
    {
        dns->wait_response_client = 1;
        ev.events = EPOLLIN|EPOLLOUT;
        ev.data.fd = dnsListenFd;
        epoll_ctl(dns_efd, EPOLL_CTL_MOD, dnsListenFd, &ev);
    }

    return 0;
}

void http_out(dns_t *out)
{
    int write_len;
    
    //puts("writing");
    write_len = write(out->fd, out->http_request, out->http_request_len);
    if (write_len == out->http_request_len)
    {
        //puts("write success");
        free(out->http_request);
        ev.events = EPOLLIN|EPOLLET;
        ev.data.ptr = out;
        epoll_ctl(dns_efd, EPOLL_CTL_MOD, out->fd, &ev);
    }
    else if (write_len > 0)
    {
        //puts("write a little");
        out->http_request_len -= write_len;
        xmemcpy(out->http_request, out->http_request + write_len, out->http_request_len);
    }
    else
    {
        //puts("write error");
        free(out->http_request);
        epoll_ctl(dns_efd, EPOLL_CTL_DEL, out->fd, NULL);
        close(out->fd);
        out->query_type = 0;
    }
}

void http_in(dns_t *in)
{
    char *ip_ptr, *p;
    int len, i;
    
    len = read(in->fd, http_rsp, HTTP_RSP_SIZE);
    if (len <= 0)
    {
        in->query_type = 0;
        epoll_ctl(dns_efd, EPOLL_CTL_DEL, in->fd, NULL);
        close(in->fd);
        return;
    }
    http_rsp[len] = '\0';
    //printf("[%s]\n", http_rsp);
    p = strstr(http_rsp, "\n\r");
    if (p)
    {
        //部分代理服务器使用长连接，第二次读取数据才读到域名的IP
        if (p + 3 - http_rsp >= len)
            return;
        p += 3;
    }
    else
        p = http_rsp;
    epoll_ctl(dns_efd, EPOLL_CTL_DEL, in->fd, NULL);
    close(in->fd);
    in->reply = (char *)malloc(6);
    if (in->reply == NULL)
        goto error;
    do {
        if (*p == '\n')
            p++;
        /* 匹配IP */
        if (*p  > 57 || *p < 49)
            continue;
        for (i = 0, ip_ptr = p, p = strchr(ip_ptr, '.'); ; ip_ptr = p + 1, p = strchr(ip_ptr, '.'))
        {
            if (i < 3)
            {
                if (p == NULL)
                    goto error;
                //查找下一行
                if (p - ip_ptr > 3)
                    break;
                in->reply[++i] = atoi(ip_ptr);
            }
            else
            {
                in->reply[i+1] = atoi(ip_ptr);
                in->reply[0] = 4;
                in->reply[5] = '\0';
                build_dns_response(in);
                if (cfp)
                    cache_record(in);
                else
                    free(in->reply);
                return;
            }
        }
    } while ((p = strchr(p, '\n')) != NULL);
    
    error:
    free(in->reply);
    in->reply = NULL;
    if (build_dns_response(in) == 1)
        in->query_type = 0;
}

void new_client()
{
    dns_t *dns;
    int i, len;
    
    for (i = 0; i < DNS_MAX_CONNECTION; i++)
        if (dns_list[i].query_type == 0)
            break;
    if (i == DNS_MAX_CONNECTION)
        return;
    dns = &dns_list[i];
    len = recvfrom(dnsListenFd, &dns->dns_req, DATA_SIZE, 0, (struct sockaddr *)&dns->src_addr, &addr_len);
    //dns请求必须大于18
    if (len <= 18)
        return;
    /* 查询缓存 */
    if (cachePath)
    {
        dns->reply = cache_lookup(dns->dns_req + 12, dns);
        if (dns->reply != NULL)
        {
            if (build_dns_response(dns) != 0)
                dns->query_type = 0;
            return;
        }
    }
    if (parse_dns_request(dns->dns_req, dns) != 0)
    {
        if (dns->query_type == 12)
        {
            dns->reply = PTR_domain;
            if (build_dns_response(dns) != 0)
                dns->query_type = 0;
        }
        else
            dns->query_type = 0;
        return;
    }
    dns->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (dns->fd < 0)
    {
        free(dns->http_request);
        dns->query_type = 0;
        return;
    }
    fcntl(dns->fd, F_SETFL, O_NONBLOCK);
    connect(dns->fd, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    /* "GET /d?dn=" + dns->host + " HTTP/1.0\r\nHost: " + host_value + "\r\n\r\n" */
    dns->http_request = (char *)malloc(10 + strlen(dns->host) + 17 + host_value_len + 4 + 1);
    free(dns->host);
    if (dns->http_request == NULL)
    {
        close(dns->fd);
        dns->query_type = 0;
        return;
    }
    dns->http_request_len = sprintf(dns->http_request, "GET /d?dn=%s HTTP/1.0\r\nHost: %s\r\n\r\n", dns->host, host_value);
    ev.events = EPOLLOUT|EPOLLERR|EPOLLET;
    ev.data.ptr = dns;
    if (epoll_ctl(dns_efd, EPOLL_CTL_ADD, dns->fd, &ev) != 0)
    {
        close(dns->fd);
        free(dns->http_request);
        dns->query_type = 0;
        return;
    }
}

void start_server()
{
    int n;

    fcntl(dnsListenFd, F_SETFL, O_NONBLOCK);
    dns_efd = epoll_create(DNS_MAX_CONNECTION+1);
    if (dns_efd < 0)
    {
        perror("epoll_create");
        return;
    }
    ev.data.fd = dnsListenFd;
    ev.events = EPOLLIN;
    epoll_ctl(dns_efd, EPOLL_CTL_ADD, dnsListenFd, &ev);
    memset(dns_list, 0, sizeof(dns_list));

    //设置IP查询域名的大小
    PTR_domain[0] = sizeof(PTR_domain) - 1;
    while (1)
    {
        n = epoll_wait(dns_efd, evs, DNS_MAX_CONNECTION + 1, -1);
        while (n-- > 0)
        {
            if (evs[n].data.fd == dnsListenFd)
            {
                if (evs[n].events & EPOLLIN)
                {
                    //puts("accept client");
                    new_client();
                    //puts("accepted client");
                }
                if (evs[n].events & EPOLLOUT)
                {
                    //puts("response clients");
                    respond_clients();
                    //puts("responsed clients");
                }
            }
            else if (evs[n].events & EPOLLIN)
            {
                //puts("data in");
                http_in(evs[n].data.ptr);
                //puts("data in handled");
            }
            else if (evs[n].events & EPOLLOUT)
            {
                //puts("data out");
                http_out(evs[n].data.ptr);
                //puts("data out handled");
            }
            else if (evs[n].events & EPOLLERR)
            {
                dns_t *err = evs[n].data.ptr;
                free(err->http_request);
                epoll_ctl(dns_efd, EPOLL_CTL_DEL, err->fd, NULL);
                close(err->fd);
                err->query_type = 0;
            }
        }
    }
}

int udp_listen(char *ip, int port)
{
    int fd;
    struct sockaddr_in addr;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("udp socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("udp bind");
        exit(1);
    }

    return fd;
}

int main(int argc, char *argv[])
{
    char *p;
    int opt;
    
    while ((opt = getopt(argc, argv, "d:l:c:L:H:h")) != -1)
    {
        switch (opt)
        {
            case 'd':
                p = strchr(optarg, ':');
                if (p)
                {
                    dst_addr.sin_port = htons(atoi(p+1));
                    *p = '\0';
                }
                else
                    dst_addr.sin_port = htons(80);
                dst_addr.sin_addr.s_addr = inet_addr(optarg);
                dst_addr.sin_family = AF_INET;
                if (p && host_value == NULL)
                {
                    *p = ':';
                    host_value = optarg;
                }
            break;
            
            case 'l':
                p = strchr(optarg, ':');
                if (p)
                {
                    *p = '\0';
                    dnsListenFd = udp_listen(optarg, atoi(p+1));
                }
                else
                    dnsListenFd = udp_listen("127.0.0.1", atoi(optarg));
            break;
            
            case 'c':
                cachePath = optarg;
                read_cache_file();
            break;
            
            case 'L':
                cacheLimit = atoi(optarg);
            break;
            
            case 'H':
                host_value = optarg;
            break;
            
            case 'h':
                help(0);
            break;
        }
    }
    if (dnsListenFd < 0)
        help(1);
    if (daemon(1, 1))
    {
        perror("daemon");
        return 1;
    }
    //忽略pipe信号
    signal(SIGPIPE, SIG_IGN);
    //程序结束时写入缓存
    signal(SIGTERM, write_dns_cache);
    //设置IP查询域名的大小
    PTR_domain[0] = sizeof(PTR_domain) - 1;
    host_value_len = strlen(host_value);
    start_server();

    return 0;
} 
