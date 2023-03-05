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
{ //ip��ַ 
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
} ip_address;

typedef struct mac_address
{//mac��ַ 
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
    u_char b5;
    u_char b6;
} mac_address;

typedef struct ethe_header
{ //mac֡�ײ� 
    mac_address mac_dest_address;
    mac_address mac_source_address;
    u_short ether_type;
} ethe_header;

typedef struct ip_header
{ //ip��ַ�ײ� 
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
{ //UDP�ײ� 
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udp_header;

typedef struct tcp_header
{ //TCP�ײ� 
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
char judge; //�ж��Ƿ�Ҫ�����׽���ı�����Ϣ
int length;

int main()
{
    pcap_if_t* alldevs, * device;//alldevsָ��pcap_if_t�ṹ(�ӿ���Ϣ�Ľṹ�壩�б��ָ��
    int i = 0;      //�豸����
    int iNum;
    u_int netmask;  //��������
    struct bpf_program fcode;
    pcap_t* adhandle;   //��������Ϣ
    char errbuf[PCAP_ERRBUF_SIZE];
    //�޸�������Ը��Ĳ�������ݰ�ʹ�õ�Э������ ��ip and udp����ֻ����ipv4�ϵ�udpЭ�飩
    char packet_filter[] = "ip and udp and src port 8000";//Դ�Զ˿�108�����ݰ�;

    //pcap_findalldevs_ex()���ڻ�ȡ��ǰ�������豸�б��洢��alldevs�����Ը��ݸú����������豸�б�ѡ����Ҫ������̽���豸����������̫���ڻ�����������֮��
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    { 
        fprintf(stderr, "�޷��������豸:%s\n", errbuf);
        return 1;
    }
    //��ȡ�豸�б�ɹ�����ӡ�б�
    for (device = alldevs; device != NULL; device = device->next)
    {  
        if (i == 0)     //��һ�ν���ѭ�����豸Ϊ0
        {
            printf("�밴CTRL + C�˳�!\n\n");
            printf("�����豸����:\n");
        }
        printf("%d. %s\n", ++i, device->name);
        if (device->description)
            printf(" (%s)\n", device->description);
        else
            printf("û���豸������Ϣ!");
    }

    printf("��ѡ�������豸�ӿ�:(1 - %d):", i);
    scanf_s("%d", &iNum);
    getchar();
    if (iNum < 1 || iNum > i)
    {
        printf("�豸������!\n");
        pcap_freealldevs(alldevs);  //�ͷŽӿ��б�
        return -1;
    }
    //��ת����ѡ�豸 
    for (device = alldevs, i = 0; i < iNum - 1; device = device->next, i++);

    // �������� 
    if ((adhandle = pcap_open(device->name,  // �豸��
        65536,     // Ҫ��׽�����ݰ��Ĳ��� 
                   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ�����ݣ�����������ȫ���˿ڣ�
        PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
        1000,      // ��ȡ��ʱʱ��
        NULL,      // Զ�̻�����֤
        errbuf     // ���󻺳��
    )) == NULL)
    {
        fprintf(stderr, "\n���ܴ���������\n");
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //pcap_datalink�����������·����ethernet��802.11������ʵ��ֻ������̫����
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nϵͳ������·����!\n");
        pcap_freealldevs(alldevs); //�ͷ��豸�б� 
        return -1;
    }

    if (device->addresses != NULL) //��ýӿڵ�һ����ַ������
        netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    else //����ӿ�û�е�ַ����ô���Ǽ���һ��C�������
        netmask = 0xffff00;

    //pcap_compile���ù�����packet_filter��
    // ahandle����pcap�Ự�����fcode��ű����Ժ�Ĺ���packet_filter��ʾ���˹���1��ʾ�����Ż������һ���Ǽ����ӿڵ���������
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    { 
        fprintf(stderr, "���ܼ������˸����ݱ�!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    //���ù�����
    if (pcap_setfilter(adhandle, &fcode) < 0)
    { 
        fprintf(stderr, "�������ô���!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("�������Ƿ�Ҫ�����׽���ı�����Ϣ(y/n) : ");
    scanf_s("%c", &judge);
    if (judge != 'n')
    {
        printf("������Ҫ����Ҫ���������Ϣ����(-1������) : ");
        scanf_s("%d", &length);
    }
    printf("\n���ڼ���ͨ��%s�����ݱ�...\n", device->description);
    pcap_freealldevs(alldevs); //�ͷ��豸�б�    
    pcap_loop(adhandle, 0, packet_handler, NULL); // pcap_loopѭ��ִ��packet_handler����,��ʼ��׽

    return 0;
}

void packet_handler(u_char* dumpfile, const struct pcap_pkthdr* header, const u_char* pkt_data)
{ //�ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������
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
    ip_len = (ip_hd->ver_ihl & 0xf) * 4; //ip�ײ����� 
    udp_hd = (udp_header*)((u_char*)ip_hd + ip_len);
    sport = ntohs(udp_hd->sport);
    dport = ntohs(udp_hd->dport);
    if (ip_hd->proto == 17 )
    {
        printf("Э�飺UDP");
        start = ip_len + 8;
    }
    //else if (ip_hd->proto == 6)
    //{   
    //       printf("Э�飺TCP");
    //       tcp_hd = (tcp_header*)((u_char*)ip_hd + ip_len);
    //       tcp_len = ntohs(tcp_hd->sum) >> 12;
    //       start = ip_len + tcp_len * 4;
    //}
    //else if (ip_hd->proto == 1)  //���icmpЭ�����ݰ�
    //{
    //    printf("Э�飺ICMP");
    //    start = ip_len + 23;
    //}
    //else {
    //    printf("Э�飺����");
    //}

 
    printf("                      ���ݱ��ĳ��ȣ�%d\n", header->caplen);
    printf("IPͷ�ĳ��ȣ�%d               IP�����ʱ�䣺%d\n", ip_hd->tlen, ip_hd->ttl);
    printf("ԴIP��ַ: %d.%d.%d.%d         Ŀ��IP��ַ��%d.%d.%d.%d\nԴ�˿ڣ�%d                     Ŀ�Ķ˿ڣ�%d\nԴ�����ַ: %x-%x-%x-%x-%x-%x   Ŀ�������ַ��%x-%x-%x-%x-%x-%x\n",
        ip_hd->saddr.b1, ip_hd->saddr.b2, ip_hd->saddr.b3, ip_hd->saddr.b4,
        ip_hd->daddr.b1, ip_hd->daddr.b2, ip_hd->daddr.b3, ip_hd->daddr.b4, sport, dport,
        ethe_hd->mac_source_address.b1, ethe_hd->mac_source_address.b2, ethe_hd->mac_source_address.b3,
        ethe_hd->mac_source_address.b4, ethe_hd->mac_source_address.b5, ethe_hd->mac_source_address.b6,
        ethe_hd->mac_dest_address.b1, ethe_hd->mac_dest_address.b2, ethe_hd->mac_dest_address.b3,
        ethe_hd->mac_dest_address.b4, ethe_hd->mac_dest_address.b5, ethe_hd->mac_dest_address.b6);
    //������ݲ���
    if (judge == 'y')
    {
        printf("���ݲ�������Ϊ��\n");
        if (length == -1) 
            len = (header->caplen) + 1;
        else 
            len = (length > header->caplen + 1 - start) ? (header->caplen + 1) - start : length;
        for (int i = start; (i < start + len); i++)
        {
            printf("%.2x ", pkt_data[i - 1]); //Ҳ���Ը�Ϊ %c �� ascii����ʽ����� 
            if ((i % LINE_LEN) == 0) 
                printf("\n");
        }
        printf("\n\n");
    }
}