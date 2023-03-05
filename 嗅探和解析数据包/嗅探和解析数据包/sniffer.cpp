#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"ws2_32.lib")
#include <pcap.h>
#include <winsock2.h>
#pragma warning(disable:4996)
#pragma warning(disable:4430)
#define HAVE_REMOTE
#define LINE_LEN 16
#define _CRT_SECURE_NO_WARNINGS 1
//#include "winsock.h"
#include <string.h>
#include<time.h>
#include<stdio.h>
#include "pcap.h"
#include<iostream>
using namespace std;

typedef struct ip_address
{ //ip地址 
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
} ip_address;

typedef struct mac_address
{//mac地址 
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
    u_char b5;
    u_char b6;
} mac_address;

typedef struct ethe_header
{ //mac帧首部 
    mac_address mac_dest_address;
    mac_address mac_source_address;
    u_short ether_type;
} ethe_header;

typedef struct ip_header
{ //ip地址首部 
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    ip_address  saddr;
    ip_address  daddr;
    u_int   op_pad;
} ip_header;

typedef struct udp_header
{ //UDP首部 
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udp_header;

typedef struct tcp_header
{ //TCP首部 
    u_short sport;
    u_short dport;
    u_int num;
    u_int ack;
    u_short sum;
    u_short windonw;
    u_short crc;
    u_short ugr;
} tcp_header;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const  u_char* pkt_data);
char judge; //判断是否要输出捕捉到的报文信息
int length;

int main()
{
    pcap_if_t* alldevs, * device;//alldevs指向pcap_if_t结构(接口信息的结构体）列表的指针
    int i = 0;      //设备个数
    int iNum;
    u_int netmask;  //子网掩码
    struct bpf_program fcode;
    pcap_t* adhandle;   //适配器信息
    char errbuf[PCAP_ERRBUF_SIZE];
    //修改这里可以更改捕获的数据包使用的协议类型 （ip and udp代表只接收ipv4上的udp协议）
    char packet_filter[] = "ip and udp and src port 8000";//源自端口108的数据包;

    //pcap_findalldevs_ex()用于获取当前主机的设备列表，存储至alldevs。可以根据该函数给出的设备列表选定需要进行嗅探的设备，例如是以太网口还是无线网卡之类
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    { 
        fprintf(stderr, "无法打开网络设备:%s\n", errbuf);
        return 1;
    }
    //获取设备列表成功，打印列表
    for (device = alldevs; device != NULL; device = device->next)
    {  
        if (i == 0)     //第一次进入循环，设备为0
        {
            printf("请按CTRL + C退出!\n\n");
            printf("网络设备如下:\n");
        }
        printf("%d. %s\n", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf("没有设备描述信息!");
    }

    printf("请选择网络设备接口:(1 - %d):", i);
    scanf_s("%d", &iNum);
    getchar();
    if (iNum < 1 || iNum > i)
    {
        printf("设备不存在!\n");
        pcap_freealldevs(alldevs);  //释放接口列表
        return -1;
    }
    //跳转到已选设备 
    for (device = alldevs, i = 0; i < iNum - 1; device = device->next, i++);

    // 打开适配器 
    if ((adhandle = pcap_open(device->name,  // 设备名
        65536,     // 要捕捉的数据包的部分 
                   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容（打开适配器的全部端口）
        PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
        1000,      // 读取超时时间
        NULL,      // 远程机器验证
        errbuf     // 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\n不能打开适配器！\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //pcap_datalink检测适配器链路层是ethernet或802.11（本次实验只考虑以太网）
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\n系统网卡链路出错!\n");
        pcap_freealldevs(alldevs); //释放设备列表 
        return -1;
    }

    if (device->addresses != NULL) //获得接口第一个地址的掩码
        netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    else //如果接口没有地址，那么我们假设一个C类的掩码
        netmask = 0xffff00;

    //pcap_compile配置过滤器packet_filter；
    // ahandle代表pcap会话句柄，fcode存放编译以后的规则，packet_filter表示过滤规则，1表示进行优化，最后一个是监听接口的子网掩码
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    { 
        fprintf(stderr, "不能监听过滤该数据报!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode) < 0)
    { 
        fprintf(stderr, "过滤设置错误!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("请输入是否要输出捕捉到的报文信息(y/n) : ");
    scanf_s("%c", &judge);
    if (judge != 'n')
    {
        printf("请输入要限制要输出报文信息长度(-1不限制) : ");
        scanf_s("%d", &length);
    }
    printf("\n正在监听通过%s的数据报...\n", device->description);
    pcap_freealldevs(alldevs); //释放设备列表    
    pcap_loop(adhandle, 0, packet_handler, NULL); // pcap_loop循环执行packet_handler函数,开始捕捉

    return 0;
}

void packet_handler(u_char* dumpfile, const struct pcap_pkthdr* header, const u_char* pkt_data)
{ //回调函数，当收到每一个数据包时会被libpcap所调用
    if (header->caplen > 400) 
        return;
    int len;
    ip_header* ip_hd;
    udp_header* udp_hd;
    tcp_header* tcp_hd;
    ethe_header* ethe_hd;
    int ip_len, tcp_len, start = 0;
    u_short sport, dport;


    ethe_hd = (ethe_header*)pkt_data;
    ip_hd = (ip_header*)(pkt_data + 14);
    ip_len = (ip_hd->ver_ihl & 0xf) * 4; //ip首部长度 
    udp_hd = (udp_header*)((u_char*)ip_hd + ip_len);
    sport = ntohs(udp_hd->sport);
    dport = ntohs(udp_hd->dport);
    if (ip_hd->proto == 17 )
    {
        printf("协议：UDP");
        start = ip_len + 8;
    }
    //else if (ip_hd->proto == 6)
    //{   
    //       printf("协议：TCP");
    //       tcp_hd = (tcp_header*)((u_char*)ip_hd + ip_len);
    //       tcp_len = ntohs(tcp_hd->sum) >> 12;
    //       start = ip_len + tcp_len * 4;
    //}
    //else if (ip_hd->proto == 1)  //输出icmp协议数据包
    //{
    //    printf("协议：ICMP");
    //    start = ip_len + 23;
    //}
    //else {
    //    printf("协议：其它");
    //}

 
    printf("                      数据报的长度：%d\n", header->caplen);
    printf("IP头的长度：%d               IP包存活时间：%d\n", ip_hd->tlen, ip_hd->ttl);
    printf("源IP地址: %d.%d.%d.%d         目的IP地址：%d.%d.%d.%d\n源端口：%d                     目的端口：%d\n源物理地址: %x-%x-%x-%x-%x-%x   目的物理地址：%x-%x-%x-%x-%x-%x\n",
        ip_hd->saddr.b1, ip_hd->saddr.b2, ip_hd->saddr.b3, ip_hd->saddr.b4,
        ip_hd->daddr.b1, ip_hd->daddr.b2, ip_hd->daddr.b3, ip_hd->daddr.b4, sport, dport,
        ethe_hd->mac_source_address.b1, ethe_hd->mac_source_address.b2, ethe_hd->mac_source_address.b3,
        ethe_hd->mac_source_address.b4, ethe_hd->mac_source_address.b5, ethe_hd->mac_source_address.b6,
        ethe_hd->mac_dest_address.b1, ethe_hd->mac_dest_address.b2, ethe_hd->mac_dest_address.b3,
        ethe_hd->mac_dest_address.b4, ethe_hd->mac_dest_address.b5, ethe_hd->mac_dest_address.b6);
    //输出数据部分
    if (judge == 'y')
    {
        printf("数据部分内容为：\n");
        if (length == -1) 
            len = (header->caplen) + 1;
        else 
            len = (length > header->caplen + 1 - start) ? (header->caplen + 1) - start : length;
        for (int i = start; (i < start + len); i++)
        {
            printf("%.2x ", pkt_data[i - 1]); //也可以改为 %c 以 ascii码形式输出。 
            if ((i % LINE_LEN) == 0) 
                printf("\n");
        }
        printf("\n\n");
    }
}