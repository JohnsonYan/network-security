#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string.h>

int portScan(char *host)
{
    struct sockaddr_in sa;
    int sockfd, status;
    int i;

    for(i=1; i < 1024; i++) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        bzero(&sa, sizeof(sa));
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, host, &sa.sin_addr);
        sa.sin_port = htons(i);
        // 尝试与目标主机和端口i建立连接
        status = connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));
        if(status == -1) {
            // 如果连接失败
            close(sockfd);
            continue;
        }
        // 连接成功
        printf("connected %s:%d\n",host,i);
        close(sockfd);
    }
    return 0;
}


int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("usage: %s sa\n", argv[0]);
        exit(1);
    }
    struct hostent *h; // get ip by hostname
    char *host = NULL;
    //host = argv[1];
    if((h = gethostbyname(argv[1])) == NULL)
    {
        // 无法获取主机信息
        printf("can not find hostname\n");
        exit(1);
    }
    printf("hostname : %s\n", h->h_name);
    printf("IP address: %s\n", inet_ntoa(*((struct in_addr *)h->h_addr)));
    portScan(host);
    return 0;
}
