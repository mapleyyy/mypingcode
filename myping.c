#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<unistd.h>
#include<netinet/ip_icmp.h>
#include<netdb.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pthread.h>


struct sockaddr_in dst_addr;
struct sockaddr_in recv_addr;
int sockfd = 0, bytes = 56;//socket为套接口
int num_send_pk=0,num_recv_pk=0;//记录发送包的次数以及接受到的包的个数
struct timeval recvtime;
char icmp_pkt[1024] = {0};
char recv_pkt[1024] = {0};  //用来保存发送的和接收到的icmp报文
pid_t pid;

void statistics();
int in_chksum(unsigned short *buf, int size);
int pack(int send_pkt);
void *send_ping();
int unpack(char *recv_pkt, int size);
void *recv_ping();
void tv_sub(struct timeval *out,struct timeval *in);

int main(int argc, char **argv)
{
	int size = 50 * 1024;  //设置接受缓冲区大小
	int ttl = 64;  //设置ttl值
	pthread_t send_id,recv_id;
	struct protoent *protocol = NULL;
	struct in_addr ipv4_addr;
	struct hostent *ipv4_host;
	int errno;

	if (argc < 2)
    {
        printf("usage: ./ping <host>\n");
        return -1;
    }
	if ((protocol = getprotobyname("icmp")) == NULL)
    {
        printf("unkown protocol\n");
        return -1;
    }  //获取icmp相关协议信息

	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
        printf("socket fail\n");
        return -1;
    }  //创建套接口
		setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));  //设置缓冲区
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));  //设置TLL生存时间


		//设置ip地址,注意不需要设置端口号,因为是ICMP
		memset(&dst_addr,0,sizeof(dst_addr));
		dst_addr.sin_family=AF_INET;
		errno = inet_aton(argv[1], &ipv4_addr);
    if (errno == 0)
    {
        ipv4_host = gethostbyname(argv[1]);//可以通过网址,即name获取目标ip地址
        if (NULL == ipv4_host)
        {
            printf("connect: Invalid argument\n");
            return -1;
        }
        memcpy(&(dst_addr.sin_addr), ipv4_host->h_addr, sizeof(struct in_addr));
    }
    else
    {
        memcpy(&(dst_addr.sin_addr), &(ipv4_addr.s_addr), sizeof(struct in_addr));
    }


		printf("PING %s (%s) %d bytes of data.\n",argv[1], inet_ntoa(dst_addr.sin_addr), bytes);  //打印ping对象的基本信息
    signal(SIGINT, statistics);  //在用户输入ctrl+c后运行statistics这个函数

		pid=getpid();//以进程id作为标记,防止有多个进程同时ping,导致收到报文错乱
		errno = pthread_create(&send_id, NULL, send_ping, NULL);
    if (errno != 0)
    {
        printf("send_ping thread fail\n");
        return -1;
    }  //创建发送ping报文的线程
    errno = pthread_create(&recv_id, NULL, recv_ping, NULL);
    if (errno != 0)
    {
        printf("recv_ping thread fail\n");
        return -1;
    }  //创建接受数据的线程
    pthread_join(send_id, NULL);
    pthread_join(recv_id, NULL);  //使主线程等待,等待两个线程

    return 0;
}
//校验算法,计算出校验位
int in_chksum(unsigned short *buf, int size)
{
    int nleft = size;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short ans = 0;

    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char *) (&ans) = *(unsigned char *)w;
        sum += ans;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    ans = ~sum;
    return ans;
}

int pack(int send_pkt)
{
		struct icmp* pkt=(struct icmp*)icmp_pkt;
		struct timeval *time=NULL;
		pkt->icmp_type=ICMP_ECHO;//报文类型

		pkt->icmp_cksum = 0;  //报文校验码
		pkt->icmp_seq= htons(num_send_pk);  //报文序列号
		pkt->icmp_id=pid;//报文id
		time=(struct timeval*)pkt->icmp_data;
		gettimeofday(time,NULL);//报文数据设置为当前发送时间
		pkt->icmp_cksum = in_chksum((unsigned short *)pkt, bytes + 8);//设置报文校验码

    return bytes + 8;

}

void *send_ping()
{
	int send_bytes=0;
	while(1)//通过死循环一直发送icmp报文
	{
		num_send_pk++;//报文序号加一
		send_bytes=pack(num_send_pk);//打包数据包
		int errno=sendto(sockfd,icmp_pkt,send_bytes,0,(struct sockaddr*)&dst_addr,sizeof(dst_addr));//发送数据包
		if(errno==-1)
		{
			printf("send fail\n");
			sleep(1);
			continue;
		}//如果发送失败,打印信息,并且休眠一秒后继续发送
		sleep(1);//进程休眠一秒,应该是为了方便返回数据的观察
	}
}

int unpack(char *recv_pkt, int size)
{
		struct iphdr *ip = NULL;
		int iphdrlen;
		struct icmp *icmp;
		struct timeval *tvsend;


		ip = (struct iphdr *)recv_pkt;//首先为了读取ip报头的长度,获取ip报头的内容
		iphdrlen = ip->ihl<<2;//因为ip->ihl只有4位,所以ihl需要乘以4才是报文头长度,所以ip报文长度应该是4的倍数
		printf("%X\n",iphdrlen);
		printf("%X  %X\n",recv_pkt,&recv_pkt[0]);
		icmp = (struct icmp*)(recv_pkt+iphdrlen);//将报文移动ip报头长度,则是icmp报文的内容
		printf("%X\n",icmp);
		size -= iphdrlen;//获取icmp报文的长度
		if (size < 8)
		{
				printf("ICMP size is less than 8\n");
				return -1;
		}

		if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
		{
				tvsend = (struct timeval *)icmp->icmp_data;
				tv_sub(&recvtime, tvsend);
				double rtt;

				rtt= recvtime.tv_sec * 1000 + (double)recvtime.tv_usec / (double)1000;
				printf("%d byte from %s: icmp_seq = %d ttl=%d rtt=%.3fms\n",
						size,inet_ntoa(recv_addr.sin_addr),ntohs(icmp->icmp_seq), ip->ttl, rtt);
		}
		else
		{
				return -1;
		}
		return 0;
}
void *recv_ping()
{
		fd_set read_set;//文件句柄,用于select函数监听套接口

		struct timeval time;
		time.tv_sec=5;//设置监听时间
		time.tv_usec=0;
		int ret=0,num_read=0,recv_len = 0;//ret用于记录select返回值,num_read用于记录recvfrom接收到的长度,recv_len用于记录地址长度
		recv_len=sizeof(recv_addr);
		while(1)
		{
				FD_ZERO(&read_set);//将read_set中的各项置0
				FD_SET(sockfd,&read_set);//将sockfd套接口对应项置1
				ret=select(sockfd+1,&read_set,NULL,NULL,&time);//用于监听一个read组,在time时间内没有任何接口有消息则返回

				if(ret<=0)
				{
					continue;

				}
				else if(FD_ISSET(sockfd,&read_set))
				{
					//从套接口读取报文
					num_read=recvfrom(sockfd,recv_pkt,sizeof(recv_pkt),0,(struct sockaddr*)&recv_addr,(socklen_t*)&recv_len);
					if(num_read<0)
							continue;
					struct timeval *recv_time=&recvtime;
					gettimeofday(recv_time,NULL);//获取收到报文的时间
					if(unpack(recv_pkt,num_read)==-1)//解包
					{
						printf("unpack fail\n");
						continue;
					}
					num_recv_pk++;
				}
		}
}
//计算发送到收到报文的时间
void tv_sub(struct timeval *out,struct timeval *in)
{
		if ((out->tv_usec-=in->tv_usec) < 0)
		{
				--out->tv_sec;
				out->tv_usec += 1000000;
		}

		out->tv_sec -= in->tv_sec;
}
void statistics()
{
	//统计发出与接收报文的数量关系
		printf("\n--- %s ping statistics ---\n", inet_ntoa(dst_addr.sin_addr));
		printf("%d packets transmitted, %d received, %.3f%c packet loss\n",
				num_send_pk, num_recv_pk, (float)100*(num_send_pk - num_recv_pk)/num_send_pk, '%');
		close(sockfd);

		exit(0);
}
