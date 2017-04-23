#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string.h>

#define IPLEN 16
#define PACKET_SIZE 4096
#define TIME_OUT_TIME 3
unsigned short cal_chksum(unsigned short *addr,int len)
{
    int sum=0;
    int nleft = len;
    unsigned short *w = addr;
    unsigned short answer = 0;
    /* 把ICMP报头二进制数据以2字节为单位累加起来 */
    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
    /* 若ICMP报头为奇数个字节，会剩下最后一字节，
     * 把最后一个字节视为一个2字节数据的高字节，
     * 这2字节数据的低字节为0，继续累加
     * */
    if(nleft == 1){
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;    /* 这里将 answer 转换成 int 整数 */
    }
    sum = (sum >> 16) + (sum & 0xffff);        /* 高位低位相加 */
    sum += (sum >> 16);        /* 上一步溢出时，将溢出位也加到sum中 */
    answer = ~sum;             /* 注意类型转换，现在的校验和为16位 */
    return answer;
}
char* splitIP(char *host, char *ip)
{
    int i;
    // strtok会修改host，所以新建一个变量来防止这种情况发生
    char buf[IPLEN];
    char *pbuf=buf;
    strcpy(pbuf,host);
    char *token = NULL;
    char *save = NULL;
    token = strtok_r(pbuf, ".",&save);
    strcat(ip, token);
    for(i = 0; i < 2; i++)
    {
        token = strtok_r(NULL, ".",&save);
        strcat(ip, ".");
        strcat(ip, token);
    }
    strcat(ip, ".");
    return ip;
}

int portScan(char *host)
{
    struct sockaddr_in sa;
    int sockfd, status;
    int i,j;
    char ip[IPLEN],*ip_ptr;
    char ip_number[3];
    for(i=2; i < 256; i++)
    {
        memset(ip, '\0', IPLEN);
        memset(ip_number, '\0', 3);
        ip_ptr = ip;
        // 分割ip地址
        ip_ptr = splitIP(host, ip);
        sprintf(ip_number, "%d", i);
        strcat(ip_ptr, ip_number);
        printf("222 %s\n", ip_ptr);
        for(j=1; j < 1024; j++) {
            // 建立套接字
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            bzero(&sa, sizeof(sa));
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip_ptr, &sa.sin_addr);
            sa.sin_port = htons(j);
            // 尝试与目标主机和端口i建立连接
            status = connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));
            if(status == -1) {
                // 如果连接失败
                close(sockfd);
                continue;
            }
            // 连接成功
            printf("connected %s:%d\n",ip_ptr,j);
            close(sockfd);
        }
    }
    return 0;
}

int hostscan(char *ip) {

}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("usage: %s ip\n", argv[0]);
        exit(1);
    }
    char *host = NULL;
    host = argv[1];
    printf("Destination IP-address:%s\n", host);
    portScan(host);
    return 0;
}
