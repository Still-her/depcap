#include "mdl_mng.h"
#include "cm_spucfg.h"
#include "sm_scree.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "smgp.h"
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include "properties.h"
#include <signal.h>
#include <iomanip>
#include "tab_r.h"

 
#include <string.h>  
#include <unistd.h>  
#include <stdint.h>  
#include <errno.h>    
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/time.h>
#include "sm_trace2.h"

#include<unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include "cmn.h"
#include "conf.h"
using namespace std;
#define TCPDUMP_MAGIC       0xa1b2c3d4  
#define PCAP_VERSION_MAJOR 2  
#define PCAP_VERSION_MINOR 4  



const U32 MOD_ADLER     = 65521;
const U32 VTAG          = 0x01010101;
const U16 TYPEUBE       = 0x0300;
const U32 M3UA_ppid     = 0x00000003;

struct tcpinfo
{
    struct firtinfo
    {
        unsigned int   ip;
        unsigned short port;
        unsigned int seq;
        unsigned int nextseq;
    }fir;
    struct sectinfo
    {
        unsigned int   ip;
        unsigned short port;
        unsigned int seq;
        unsigned int nextseq;
    }sec;
    unsigned char isfirtosec;
};

struct stcpinfo
{
    struct firstinfo
    {
        unsigned int   ip;
        unsigned short port;
		unsigned int   datanum;  
        unsigned int   tsn;
		unsigned short ssn;
		unsigned int   acktsn;

    }fir;
    struct secstinfo
    {
        unsigned int   ip;
        unsigned short port;
        unsigned int   datanum;  
        unsigned int   tsn;
		unsigned short ssn;
		unsigned int   acktsn;
    }sec;
    unsigned char isfirtosec;
	U16 typeube;
};

struct m3uainfopkg
{
    struct localinfo
    {
        unsigned int   ip;
        unsigned short port;
		unsigned int   OPC;
		unsigned int   datanum;  
        unsigned int   tsn;
		unsigned short ssn;
		unsigned int   acktsn;

    }fir;
    struct spuinfo
    {
        unsigned int   ip;
        unsigned short port;
		unsigned short DPC;
        unsigned int   datanum;  
        unsigned int   tsn;
		unsigned short ssn;
		unsigned int   acktsn;
    }sec;
	U16 typeube;
};

struct pcap_file_header
{
    unsigned int     magic;
    unsigned short   version_major;
    unsigned short   version_minor;
    int              thiszone;       //gmt to local correction
    unsigned int     sigfigs;        //accuracy of timestamps
    unsigned int     snaplen;        //max length saved portion of each pkt
    unsigned int     linktype;       //data link type (LINKTYPE_*)
};

//TCP伪头部
struct psd
{
    struct in_addr src;
    struct in_addr dst;
    char zero;
    char p;
    unsigned short len;
};

struct sctp_header
{
    U16     sport;
    U16     dport;
    U32     vtag;
    U32     checksum;
};

struct sctp_headerack
{
    U16     sport;
    U16     dport;
    U32     vtag;
    U32     checksum;

	U16     acktypeube;
    U16     acklength;
    U32     acktsn;
    U32     rwnd;
	U32     tsns;
};

struct sctp_header_data 
{
    U16     typeube;
    U16     length;
    U32     tsn;
    U16     sid;
    U16     ssn;
    U32     ppid;
};

struct m3ua_header_data 
{
    U8      ver;
    U8      res;
    U8      cla;
    U8      tpe;
    U32     len;
    U16     tag;
	U16     parlen;
	U32     opc;
	U32		dpc;
	U8		si;
	U8      ni;
	U8		mp;
	U8		sls;
};

struct tostcpinfo
{
	U16      flags;
	traninfo trinf;
	pkgtype  type;
};

struct tom3uainfo
{
	U16      flags;
	m3uainfo trinf;
};

struct job
{
    void* (*callback_function)(void *arg);    //线程回调函数
    void *arg;                                //回调函数参数
    struct job *next;
};

struct threadpool
{
    int thread_num;                   //线程池中开启线程的个数
    int queue_max_num;                //队列中最大job的个数
    struct job *head;                 //指向job的头指针
    struct job *tail;                 //指向job的尾指针
    pthread_t *pthreads;              //线程池中所有线程的pthread_t
    pthread_mutex_t mutex;            //互斥信号量
    pthread_cond_t queue_empty;       //队列为空的条件变量
    pthread_cond_t queue_not_empty;   //队列不为空的条件变量
    pthread_cond_t queue_not_full;    //队列不为满的条件变量
    int queue_cur_num;                //队列当前的job个数
    int queue_close;                  //队列是否已经关闭
    int pool_close;                   //线程池是否已经关闭
};

void show_bin1(U8 *buf, int len, const char *lab)
{
	if(lab)
		printf("%s: ", lab);

	for(int i=0; i<len; i++)
	{
		printf("%02x ", buf[i]);
		if(i%16 == 15)
			printf("\n");
	}
	printf("\n");
}

//================================================================================================
//函数名：                   threadpool_init
//函数描述：                 初始化线程池
//输入：                    [in] thread_num     线程池开启的线程个数
//                         [in] queue_max_num  队列的最大job个数 
//输出：                    无
//返回：                    成功：线程池地址 失败：NULL
//================================================================================================
struct threadpool* threadpool_init(int thread_num, int queue_max_num);

//================================================================================================
//函数名：                    threadpool_add_job
//函数描述：                  向线程池中添加任务
//输入：                     [in] pool                  线程池地址
//                          [in] callback_function     回调函数
//                          [in] arg                     回调函数参数
//输出：                     无
//返回：                     成功：0 失败：-1
//================================================================================================
int threadpool_add_job(struct threadpool *pool, void* (*callback_function)(void *arg), void *arg);

//================================================================================================
//函数名：                    threadpool_destroy
//函数描述：                   销毁线程池
//输入：                      [in] pool                  线程池地址
//输出：                      无
//返回：                      成功：0 失败：-1
//================================================================================================
int threadpool_destroy(struct threadpool *pool);

//================================================================================================
//函数名：                    threadpool_function
//函数描述：                  线程池中线程函数
//输入：                     [in] arg                  线程池地址
//输出：                     无  
//返回：                     无
//================================================================================================
void* threadpool_function(void* arg);

vector<tcpinfo>  vectcpinfo [17];
vector<stcpinfo> vecstcpinfo[17];
m3uainfopkg      stzm3uainfo[17];


#if 1
uint8_t mac_data[] = {  
0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x0c, 0x29, 0x1c, 0xbe, 0x75, 0x00, 0x00, 0x08, 0x00
};
uint8_t smgp_data[] = {  
0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x21, 0x01, 0x01, 0x01, 0x31, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x31, 0x35, 0x31, 0x30, 0x30, 0x39, 0x32, 0x32, 
0x34, 0x31, 0x34, 0x30, 0x30, 0x33, 0x32, 0x2b, 0x00, 0x31, 0x35, 0x31, 0x30, 0x30, 0x39, 0x32, 
0x32, 0x34, 0x31, 0x34, 0x30, 0x30, 0x33, 0x32, 0x2b, 0x00, 0x31, 0x38, 0x35, 0x36, 0x35, 0x37, 
0x36, 0x30, 0x33, 0x32, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x33, 0x35, 0x32, 0x38, 0x34, 0x30, 0x30, 0x32, 0x31, 0x37, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x64, 0x6e, 0x77, 0x75, 0x65, 
0x71, 0x66, 0x6e, 0x6e, 0x6a, 0x77, 0x65, 0x66, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
#endif
#if 0
uint8_t sccp_data[] = {  
0x09, 0x81, 0x03, 0x0e, 0x19, 0x0b, 0x92, 0x06, 0x00, 0x11, 0x04, 0x68, 0x92, 0x02, 0x04, 0x70, 
0x06, 0x0b, 0x92, 0x07, 0x00, 0x11, 0x04, 0x68, 0x42, 0x65, 0x07, 0x80, 0x08, 0x18, 0x65, 0x16, 
0x48, 0x04, 0x01, 0x00, 0x2b, 0x43, 0x49, 0x04, 0x10, 0x00, 0x00, 0x1b, 0x6c, 0x08, 0xa1, 0x06, 
0x02, 0x01, 0x01, 0x02, 0x01, 0x38};

#endif

extern sbe* get_sbe(U32 spid, U32 id);
pthread_mutex_t mutex_file;

int initm3uacfg()
{
	smscgen sgen;
	evconfig::get()->resmsconf(0, &sgen);	
	for(int i = 1; i < 17; ++i)
	{
		stzm3uainfo[i].fir.ip   = sgen.smscServiceIP;
		stzm3uainfo[i].fir.port = sgen.smscM3uaPort;
		stzm3uainfo[i].fir.OPC  = sgen.SmscSpc;
		stzm3uainfo[i].fir.tsn  = 0X00;
		
		stzm3uainfo[i].sec.ip   = sgen.spuIP;
		stzm3uainfo[i].sec.port = sgen.spuM3uaPort;
		stzm3uainfo[i].sec.DPC  = sgen.StpSpc;
		stzm3uainfo[i].fir.tsn  = 0x7FFFFFFF;
	}
	// 初始化互斥锁
    if (pthread_mutex_init(&mutex_file, NULL) != 0){
        return 1;
    }
}

int evtrace2::readtrace2()
{
	CTabR tr;
	if (tr.Open("conf/trace2.tab"))
		return -1;
	smtrace2  oc;
	const int COLS = 9;
	string ss[COLS];
	int cols;
	while(1)
	{
		cols = tr.GetRow(ss, COLS);
		if (cols < COLS)
			break;
		memset(&oc,0,sizeof(oc));
		oc.id      = atoi(ss[0].c_str());
		oc.enb     = atoi(ss[1].c_str());
		if(strlen(ss[2].c_str())>3)
		{
			strncpy((char*)oc.oa,ss[2].c_str(),21);
		}
		if(strlen(ss[3].c_str())>3)
		{
			strncpy((char*)oc.da,ss[3].c_str(),21);
		}
		oc.pp_lnk     = atoi(ss[4].c_str());
		oc.gp_lnk     = atoi(ss[5].c_str());
		oc.map_cap    = atoi(ss[6].c_str());
		if(strlen(ss[7].c_str())>3)
		{
			strncpy((char*)oc.sccp_gt,ss[7].c_str(),21);
		}
		if(strlen(ss[8].c_str()))
		{
			strncpy((char*)oc.filename,ss[8].c_str(),15);
		}
		sztrace2[oc.id] = oc;		
	}
	return 0;
}

void evtrace2::show()
{
	ostringstream os;
	smtrace2* p;
	os << "evtrace2:" << endl;
	os << setw(4) << " " << "id" << setw(4)  << " enb" <<  setw(4) << "" << "oa" << setw(4) <<  "da" \
	   << setw(4) <<  "  pp_lnk" << setw(4) <<  "  gp_lnk"  << setw(4) <<  "  map_cap"  << setw(4) <<  "  sccp_gt" << setw(4) <<  "  filename" << endl;
	for(int i = 1; i < 17; i++)
	{
		p = get(i);
		if(p)
		os << setw(4) << "" << (int)sztrace2[i].id << setw(4) << " " << (int)sztrace2[i].enb << " " << setw(4) << "" << sztrace2[i].oa << setw(4) << "" << sztrace2[i].da  \
		   << setw(4) << "" << (int)sztrace2[i].pp_lnk << setw(4) << "" << (int)sztrace2[i].gp_lnk << setw(4) << "" << (int)sztrace2[i].map_cap << setw(4) << "" << sztrace2[i].sccp_gt << setw(4) << "" << sztrace2[i].filename << endl;
	}
	cout << os.str() << endl;
}

int evtrace2::add(smtrace2 oc)
{
	if (oc.id == 0 || oc.id >= 17 || sztrace2[oc.id].id)
			return -1;
	sztrace2[oc.id] = oc;
	return 0;
}

int evtrace2::del(int id)
{
	if (id == 0 || id >= 17 || sztrace2[id].id != id)
		return -1;
	memset(&sztrace2[id],0,sizeof(smtrace2));
	return 0;
}

smtrace2* evtrace2::get(int id)
{
	if (id == 0 || id >= 17 || sztrace2[id].id == 0)
		return NULL;
	return sztrace2 + id;
}

unsigned short isnbr_trace2(char* oa, char* da)
{
	unsigned short flags = 0;
	if(NULL != oa && NULL != da)
	{
		for(int i = 1; i < 17; ++i)
		{
			if(evtrace2::get()->sztrace2[i].enb)
			{
				if(strlen((char*)evtrace2::get()->sztrace2[i].oa) && strlen((char*)evtrace2::get()->sztrace2[i].da) == 0)
				{
					if(strlen((char*)evtrace2::get()->sztrace2[i].oa) == strlen(oa) && strncmp((char*)evtrace2::get()->sztrace2[i].oa,oa,strlen(oa))==0)
					{
						flags |=  1 << (i-1);
					}
				}
				else if (strlen((char*)evtrace2::get()->sztrace2[i].da) && strlen((char*)evtrace2::get()->sztrace2[i].oa) == 0)
				{
					if(strlen((char*)evtrace2::get()->sztrace2[i].da) == strlen(da) && strncmp((char*)evtrace2::get()->sztrace2[i].da,da,strlen(da))==0)
					{
						flags |=  1 << (i-1);
					}
				}
				else if(strlen((char*)evtrace2::get()->sztrace2[i].da) && strlen((char*)evtrace2::get()->sztrace2[i].oa))
				{
					if((strlen((char*)evtrace2::get()->sztrace2[i].da) == strlen(da) && strncmp((char*)evtrace2::get()->sztrace2[i].da,da,strlen(da))==0) && \
						strlen((char*)evtrace2::get()->sztrace2[i].oa) == strlen(oa) && strncmp((char*)evtrace2::get()->sztrace2[i].oa,oa,strlen(oa))==0)
					{
						flags |=  1 << (i-1);
					}
				}
				else{}
			}
		}
	}
	return flags;
}
unsigned short islnk_trace2(char pr,char lnk)
{
	unsigned short flags = 0;

	for(int i = 1; i < 17; ++i)
	{
		if(evtrace2::get()->sztrace2[i].enb)
		{
			if(pr == 2 && (lnk == evtrace2::get()->sztrace2[i].gp_lnk || lnk >= 100))
			{
				flags |=  1 << (i-1);
			}
			else if(pr == 1 && (lnk == evtrace2::get()->sztrace2[i].pp_lnk || lnk >= 100))
			{
				flags |=  1 << (i-1);
			}
		}
	}
	return flags;
}

unsigned short ismap_trace2()
{
	unsigned short flags = 0;

	for(int i = 1; i < 17; ++i)
	{
		if(evtrace2::get()->sztrace2[i].enb)
		{
			if(evtrace2::get()->sztrace2[i].map_cap == 1)
			{
				flags |=  1 << (i-1);
			}			
		}
	}
	return flags;
}

unsigned short isgt_trace2(char* gt)
{
	unsigned short flags = 0;

	for(int i = 1; i < 17; ++i)
	{
		if(evtrace2::get()->sztrace2[i].enb)
		{
			if(strlen((char*)evtrace2::get()->sztrace2[i].sccp_gt) == strlen(gt) && strncmp((char*)evtrace2::get()->sztrace2[i].sccp_gt,gt,strlen(gt))==0)
			{
				flags |=  1 << (i-1);
			}
		}
	}
	return flags;
}

int has_nbr_trace2()
{
	for(int i = 1; i < 17; ++i)
	{
		if(evtrace2::get()->sztrace2[i].enb)
		{
			if(strlen((char*)evtrace2::get()->sztrace2[i].oa) || strlen((char*)evtrace2::get()->sztrace2[i].da))
			{
				return 1;
			}
		}
	}
	return 0;
}

int has_gt_trace2()
{
	for(int i = 1; i < 17; ++i)
	{
		if(evtrace2::get()->sztrace2[i].enb)
		{
			if(strlen((char*)evtrace2::get()->sztrace2[i].sccp_gt))
			{
				return 1;
			}			
		}
	}
	return 0;
}

traninfo getsbeinfo(char pr,int lnk, char flag)
{
	//char buff[1024];
	// = (sbe*)buff;
	sbe* te = get_sbe(pr, lnk);
	if(te)
	{
		traninfo trinf;
		if(flag == 1)
		{
			trinf.sip =  te->rip;
			trinf.sport = te->rport;
			trinf.dip = te->lip;
			trinf.dport = te->lport;
		}
		else if(flag == 2)
		{
			trinf.sip =  te->lip;
			trinf.sport = te->lport;
			trinf.dip = te->rip;
			trinf.dport = te->rport;
		}
		return trinf;
	}
}

extern "C"
void trace2_show()
{
	evtrace2::get()->show();
}

static U32 Sctpchksum(U8* buf, U32 len)
{
    //Adler-32 算法
    U32 a = 1;
    U32 b = 0;
   
    for(U32 index = 0; index < len; ++index)
    {
       a = (a + buf[index]) % MOD_ADLER; 
       b = (b + a) % MOD_ADLER;
    }

    unsigned int checksum = (b << 16) | a;
	return checksum;
}

//校验TCP函数
static unsigned short chksum(unsigned char *data,  int len)
{
    int sum=0;
    int odd = len & 0x01;
    //unsigned short *value = (unsigned short*)data;    
    while( len & 0xfffe)
    {
        sum += *(unsigned short*)data;
        data += 2;
        len -=2;
    }    
    if(odd)
    {
        unsigned short tmp = ((*data)<<8)&0xff00;
        sum += tmp;
    }
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >>16) ;       
    return ~sum;    
}


static int totcppack(FILE *fp,traninfo *trinf, int fileid)
{
	pthread_mutex_lock(&mutex_file);
	tcpinfo tcptmp;
	memset(&tcptmp,0,sizeof(tcpinfo));
	unsigned char isfindtcpinfo = 0;
    for(vector<tcpinfo>::iterator it = vectcpinfo[fileid].begin(); it !=  vectcpinfo[fileid].end();++it)
    {
    	if(it->fir.ip == trinf->sip && it->fir.port == trinf->sport && it->sec.ip == trinf->dip && it->sec.port == trinf->dport)
    	{
    		isfindtcpinfo = 1;
    		it->isfirtosec = 1;
    		it->fir.seq = it->fir.nextseq;
        	it->fir.nextseq = it->fir.seq+trinf->datalen;
    		tcptmp = *it;
    		break;
    	}
    	else if(it->fir.ip == trinf->dip && it->fir.port == trinf->dport && it->sec.ip == trinf->sip && it->sec.port == trinf->sport)
    	{
    		isfindtcpinfo = 1;
    		it->isfirtosec = 2;
    		it->sec.seq = it->sec.nextseq;
        	it->sec.nextseq = it->sec.seq+trinf->datalen;
    		tcptmp = *it;
    		break;
    	}
		else
		{
			isfindtcpinfo = 0;
			continue;
		}
    }
	if(isfindtcpinfo == 0)
	{
		tcptmp.isfirtosec = 1;
		tcptmp.fir.ip  = trinf->sip;
	    tcptmp.fir.port = trinf->sport;
	    tcptmp.fir.seq = tcptmp.fir.nextseq;
		tcptmp.fir.nextseq = trinf->datalen;
		tcptmp.sec.ip  =  trinf->dip;
	    tcptmp.sec.port = trinf->dport;	
	    vectcpinfo[fileid].push_back(tcptmp);
	}
    //xie baotou
    unsigned int pkghead[4]; 
    struct timeval tv;
    gettimeofday(&tv, NULL);  
    pkghead[0] = (unsigned int)tv.tv_sec;
    pkghead[1] = (unsigned int)tv.tv_usec;
	pkghead[2] = 16+20+32+trinf->datalen;  //16->linktype 20->iphead 20->tcphead 
    pkghead[3] = 16+20+32+trinf->datalen;  //16->linktype 20->iphead 20->tcphead

    fwrite((char *)&pkghead, sizeof(pkghead), 1, fp);
    fwrite(mac_data, 16, 1, fp);
    //xie ip head

//填充IP

   struct iphdr iphead;
   iphead.version = 4;//版本号
   iphead.ihl = 5;
   iphead.tos = 0;
   iphead.tot_len = htons(20+32+trinf->datalen);//整个数据报总长度
   iphead.id = 13;
   iphead.frag_off = 0x40;//不分段
   iphead.ttl = 255;
   iphead.protocol = IPPROTO_TCP;
   iphead.check = 0;
   iphead.saddr = trinf->sip;//这里IP只是一个代号
   iphead.daddr = trinf->dip;
   fwrite((char *)&iphead, sizeof(iphead), 1, fp);
//填充TCP
	char tcpbuf[1024];
    memset(tcpbuf, '\0', 1024);
    struct psd * psd = (struct psd *)tcpbuf; //伪头部 = 12字节
    struct tcphdr *tcphead = (struct tcphdr *)(tcpbuf+12); 
    memcpy(tcpbuf+12+32,&trinf->data,trinf->datalen);

    //伪头部 
    psd->src.s_addr = trinf->sip; //源地址
    psd->dst.s_addr = trinf->dip;
    psd->p = 6;
    psd->zero = 0;
    psd->len = htons(32+trinf->datalen);  //TCP数据包 = 64字节
    tcphead->source = htons(trinf->sport);
    tcphead->dest = htons(trinf->dport);
    if(tcptmp.isfirtosec == 1)
    { 	
    	tcphead->seq = htonl(tcptmp.fir.seq);
    	tcphead->ack_seq = htonl(tcptmp.sec.seq);
    }
    else if(tcptmp.isfirtosec == 2)  
    {
    	tcphead->seq = htonl(tcptmp.sec.seq);
    	tcphead->ack_seq = htonl(tcptmp.fir.seq);
    }  
    tcphead->doff = 8;  //TCP头部 = 8*4 = 32字节
    tcphead->psh = 1;
    tcphead->ack = 1;
    tcphead->window = htons(1024);
    tcphead->check = htons(chksum((unsigned char *)tcpbuf, 12+32+trinf->datalen)); //伪头部 + TCP数据包 = 76字节
    fwrite(tcpbuf+12, 32+trinf->datalen, 1, fp);
	pthread_mutex_unlock(&mutex_file);
	//fclose(fp); 
	return 0;
}   

static int tostcppack(FILE *fp,traninfo *trinf, int fileid)
{
	pthread_mutex_lock(&mutex_file);
	static int stcphead_len = 0;
	stcpinfo stcptmp;
	memset(&stcptmp,0,sizeof(stcptmp));
	unsigned char isfindstcpinfo = 0;
    for(vector<stcpinfo>::iterator it = vecstcpinfo[fileid].begin(); it !=  vecstcpinfo[fileid].end();++it)
    {
    	if(it->fir.ip == trinf->sip && it->fir.port == trinf->sport && it->sec.ip == trinf->dip && it->sec.port == trinf->dport)
    	{
    		isfindstcpinfo = 1;
    		it->isfirtosec = 1;
			if(it->sec.datanum == 0)
			{
				it->fir.datanum += 1;   
				
				it->typeube = 0;
				stcphead_len = sizeof(sctp_header);
			}
			else
			{
				it->sec.datanum -= 1;   
				
				it->typeube = TYPEUBE;
				it->fir.acktsn  = it->sec.tsn - it->sec.datanum;
				stcphead_len = sizeof(sctp_headerack);
			}
        	it->fir.tsn += 1;
			it->fir.ssn += 1;
    		stcptmp = *it;
    		break;
    	}
    	else if(it->fir.ip == trinf->dip && it->fir.port == trinf->dport && it->sec.ip == trinf->sip && it->sec.port == trinf->sport)
    	{
    		isfindstcpinfo = 1;
    		it->isfirtosec = 2;
    		if(it->fir.datanum == 0)
			{
				it->sec.datanum += 1;   

				it->typeube = 0;
				stcphead_len = sizeof(sctp_header);
			}
			else
			{
				it->fir.datanum -= 1;   
				
				it->typeube = TYPEUBE;
				it->sec.acktsn  = it->fir.tsn - it->fir.datanum;
				stcphead_len = sizeof(sctp_headerack);
			}
        	it->sec.tsn += 1;
			it->sec.ssn += 1;
    		stcptmp = *it;
    		break;
    	}
		else
		{
			isfindstcpinfo = 0;
			continue;
		}
    }
	if(isfindstcpinfo == 0)
	{
		stcphead_len = sizeof(sctp_header);
		stcptmp.isfirtosec = 1;
		stcptmp.fir.ip  = trinf->sip;
	    stcptmp.fir.port = trinf->sport;
		
		stcptmp.fir.datanum += 1;	
		stcptmp.fir.tsn += 1;
		stcptmp.fir.ssn += 1;

		stcptmp.sec.ip  =  trinf->dip;
	    stcptmp.sec.port = trinf->dport;	
		stcptmp.typeube = 0;
	    vecstcpinfo[fileid].push_back(stcptmp);
	}
	
    //xie baotou
    unsigned int pkghead[4]; 
    struct timeval tv;
    gettimeofday(&tv, NULL);  
    pkghead[0] = (unsigned int)tv.tv_sec;
    pkghead[1] = (unsigned int)tv.tv_usec;
	pkghead[2] = 16+20+stcphead_len+sizeof(sctp_header_data)+trinf->datalen;  
    pkghead[3] = 16+20+stcphead_len+sizeof(sctp_header_data)+trinf->datalen;  

    fwrite((char *)&pkghead, sizeof(pkghead), 1, fp);
    fwrite(mac_data, 16, 1, fp);
    //xie ip head

//填充IP

   struct iphdr iphead;
   iphead.version = 4;//版本号
   iphead.ihl = 5;
   iphead.tos = 0;
   iphead.tot_len = htons(20+stcphead_len+sizeof(sctp_header_data)+trinf->datalen);//整个数据报总长度
   iphead.id = 13;
   iphead.frag_off = 0x40;//不分段
   iphead.ttl = 255;
   iphead.protocol = 0x84;
   iphead.check = 0;
   iphead.saddr = trinf->sip;//这里IP只是一个代号
   iphead.daddr = trinf->dip;
   fwrite((char *)&iphead, sizeof(iphead), 1, fp);
//填充STCP

	struct sctp_header_data *stcphedata = NULL;
	struct sctp_header * stcphead = NULL;
	struct sctp_headerack * stcpheack = NULL;

	char stcpbuf[1024];
    memset(stcpbuf, '\0', 1024);
	if(stcptmp.typeube == 0)
	{
		stcphead = (struct sctp_header *)stcpbuf; 
		stcphedata = (struct sctp_header_data*)(stcpbuf+sizeof(sctp_header)); 
	    memcpy(stcpbuf+sizeof(sctp_header)+sizeof(sctp_header_data),&trinf->data,trinf->datalen);

	    stcphead->sport = htons(trinf->sport);
	    stcphead->dport = htons(trinf->dport);
		stcphead->vtag = htonl(VTAG);
		stcphead->checksum = 0;
	}	

    else if(stcptmp.typeube == TYPEUBE)
	{
		stcpheack = (struct sctp_headerack *)stcpbuf; 
		stcphedata = (struct sctp_header_data*)(stcpbuf+sizeof(sctp_headerack)); 
	    memcpy(stcpbuf+sizeof(sctp_headerack)+sizeof(sctp_header_data),&trinf->data,trinf->datalen);

	    stcpheack->sport = htons(trinf->sport);
	    stcpheack->dport = htons(trinf->dport);
		stcpheack->vtag = htonl(VTAG);
		stcpheack->checksum = 0;
		stcpheack->acktypeube = htons(stcptmp.typeube);
		stcpheack->acklength  = htons(0x10);
		stcpheack->acktsn     = 0;
		stcpheack->rwnd       = htonl(0x001f4000);
		stcpheack->tsns       = 0;
    }
    if(stcptmp.isfirtosec == 1)
    { 	
    	if(stcptmp.typeube == TYPEUBE)
   		stcpheack->acktsn  = htonl(stcptmp.fir.acktsn);
		stcphedata->tsn    = htonl(stcptmp.fir.tsn);
		stcphedata->ssn    = htons(stcptmp.fir.ssn);
    }
	else if(stcptmp.isfirtosec == 2)
	{
		if(stcptmp.typeube == TYPEUBE)
		stcpheack->acktsn  = htonl(stcptmp.sec.acktsn);
		stcphedata->tsn    = htonl(stcptmp.sec.tsn);
		stcphedata->ssn    = htons(stcptmp.sec.ssn);
	}
	stcphedata->typeube = htons(3);	
	stcphedata->length  = htons(sizeof(sctp_header_data) + trinf->datalen);
	stcphedata->sid = 0;
	stcphedata->ppid = htonl(M3UA_ppid);
	if(stcptmp.typeube == 0)
	{
		stcphead->checksum = htonl(Sctpchksum((U8 *)stcphedata,sizeof(sctp_header_data)+ trinf->datalen));
	}	

    else if(stcptmp.typeube == TYPEUBE)
	{
		stcpheack->checksum = htonl(Sctpchksum((U8 *)stcphedata,sizeof(sctp_header_data)+ trinf->datalen));
    }
	
	fwrite(stcpbuf, stcphead_len+sizeof(sctp_header_data)+trinf->datalen, 1, fp);
	pthread_mutex_unlock(&mutex_file);
	//fclose(fp); 
	return 0;
}   

static int tom3uapack(FILE *fp, m3uainfo *trinf, int fileid)
{
	pthread_mutex_lock(&mutex_file);
	int ppidlen = 0;
	ppidlen = (trinf->datalen)% 4 ? (4 -(trinf->datalen)%4):0;
	static int stcphead_len = 0;
	if(trinf->flag == 1)
	{
		if(stzm3uainfo[fileid].sec.datanum == 0)
		{
			stzm3uainfo[fileid].fir.datanum += 1;	
			stzm3uainfo[fileid].typeube = 0;
			stcphead_len = sizeof(sctp_header);
		}
		else
		{
			stzm3uainfo[fileid].sec.datanum -= 1;	
			stzm3uainfo[fileid].typeube = TYPEUBE;
			stzm3uainfo[fileid].fir.acktsn	= stzm3uainfo[fileid].sec.tsn - stzm3uainfo[fileid].sec.datanum;
			stcphead_len = sizeof(sctp_headerack);
		}
		stzm3uainfo[fileid].fir.tsn += 1;
		stzm3uainfo[fileid].fir.ssn += 1;
	}
	else if(trinf->flag == 2)
	{
		if(stzm3uainfo[fileid].fir.datanum == 0)
		{
			stzm3uainfo[fileid].sec.datanum += 1;	
			stzm3uainfo[fileid].typeube = 0;
			stcphead_len = sizeof(sctp_header);
		}
		else
		{
			stzm3uainfo[fileid].fir.datanum -= 1;	
			stzm3uainfo[fileid].typeube = TYPEUBE;
			stzm3uainfo[fileid].sec.acktsn	= stzm3uainfo[fileid].fir.tsn - stzm3uainfo[fileid].fir.datanum;
			stcphead_len = sizeof(sctp_headerack);
		}
		stzm3uainfo[fileid].sec.tsn += 1;
		stzm3uainfo[fileid].sec.ssn += 1;
	}

	//xie baotou
	unsigned int pkghead[4]; 
	struct timeval tv;
	gettimeofday(&tv, NULL);  
	pkghead[0] = (unsigned int)tv.tv_sec;
	pkghead[1] = (unsigned int)tv.tv_usec;
	pkghead[2] = 16+20+stcphead_len+sizeof(sctp_header_data)+sizeof(m3ua_header_data)+trinf->datalen + ppidlen;  
	pkghead[3] = 16+20+stcphead_len+sizeof(sctp_header_data)+sizeof(m3ua_header_data)+trinf->datalen + ppidlen;  

	fwrite((char *)&pkghead, sizeof(pkghead), 1, fp);
	fwrite(mac_data, 16, 1, fp);
	//xie ip head

//填充IP

   struct iphdr iphead;
   iphead.version = 4;//版本号
   iphead.ihl = 5;
   iphead.tos = 0;
   iphead.tot_len = htons(20+stcphead_len+sizeof(sctp_header_data)+sizeof(m3ua_header_data)+trinf->datalen + ppidlen);//整个数据报总长度
   iphead.id = 13;
   iphead.frag_off = 0x40;//不分段
   iphead.ttl = 255;
   iphead.protocol = 0x84;
   iphead.check = 0;
   if(trinf->flag == 1)
   {
	   iphead.saddr = stzm3uainfo[fileid].fir.ip;
	   iphead.daddr = stzm3uainfo[fileid].sec.ip;
   }
   else
   {
   	   iphead.saddr = stzm3uainfo[fileid].sec.ip;
	   iphead.daddr = stzm3uainfo[fileid].fir.ip;
   }
   fwrite((char *)&iphead, sizeof(iphead), 1, fp);
//填充STCP

	struct sctp_header_data *stcphedata = NULL;
	struct sctp_header * stcphead = NULL;
	struct sctp_headerack * stcpheack = NULL;
	struct m3ua_header_data *m3ua_head = NULL;

	char stcpbuf[2048];
	memset(stcpbuf, '\0', 1024);
	if(stzm3uainfo[fileid].typeube == 0)
	{
		stcphead = (struct sctp_header *)stcpbuf; 
		stcphedata = (struct sctp_header_data*)(stcpbuf+sizeof(sctp_header)); 
		m3ua_head = (struct m3ua_header_data *)(stcpbuf+sizeof(sctp_header)+sizeof(sctp_header_data));
		memcpy(stcpbuf+sizeof(sctp_header)+sizeof(sctp_header_data)+sizeof(m3ua_header_data),&trinf->data,trinf->datalen);

		if(trinf->flag == 1)
	    {
		   	stcphead->sport = htons(stzm3uainfo[fileid].fir.port);
			stcphead->dport = htons(stzm3uainfo[fileid].sec.port);
	    }
	    else if(trinf->flag == 2)
	    {
	   	    stcphead->sport = htons(stzm3uainfo[fileid].sec.port);
			stcphead->dport = htons(stzm3uainfo[fileid].fir.port);
	    }
		stcphead->vtag = htonl(VTAG);
		stcphead->checksum = 0;
	}	

	else if(stzm3uainfo[fileid].typeube == TYPEUBE)
	{
		stcpheack = (struct sctp_headerack *)stcpbuf; 
		stcphedata = (struct sctp_header_data*)(stcpbuf+sizeof(sctp_headerack)); 
		m3ua_head = (struct m3ua_header_data *)(stcpbuf+sizeof(sctp_headerack)+sizeof(sctp_header_data));
		memcpy(stcpbuf+sizeof(sctp_headerack)+sizeof(sctp_header_data)+sizeof(m3ua_header_data),&trinf->data,trinf->datalen);

		if(trinf->flag == 1)
		{
			stcpheack->sport = htons(stzm3uainfo[fileid].fir.port);
			stcpheack->dport = htons(stzm3uainfo[fileid].sec.port);
		}
		else if(trinf->flag == 2)
		{
			stcpheack->sport = htons(stzm3uainfo[fileid].sec.port);
			stcpheack->dport = htons(stzm3uainfo[fileid].fir.port);
		}

		stcpheack->vtag = htonl(VTAG);
		stcpheack->checksum = 0;
		stcpheack->acktypeube = htons(stzm3uainfo[fileid].typeube);
		stcpheack->acklength  = htons(0x10);
		stcpheack->acktsn	  = 0;
		stcpheack->rwnd 	  = htonl(0x001f4000);
		stcpheack->tsns 	  = 0;
	}
	if(trinf->flag == 1)
	{	
		if(stzm3uainfo[fileid].typeube == TYPEUBE)
		stcpheack->acktsn  = htonl(stzm3uainfo[fileid].fir.acktsn);
		stcphedata->tsn    = htonl(stzm3uainfo[fileid].fir.tsn);
		stcphedata->ssn    = htons(stzm3uainfo[fileid].fir.ssn);
	}
	else if(trinf->flag == 2)
	{
		if(stzm3uainfo[fileid].typeube == TYPEUBE)
		stcpheack->acktsn  = htonl(stzm3uainfo[fileid].sec.acktsn);
		stcphedata->tsn    = htonl(stzm3uainfo[fileid].sec.tsn);
		stcphedata->ssn    = htons(stzm3uainfo[fileid].sec.ssn);
	}
	stcphedata->typeube = htons(3);		
	stcphedata->length	= htons(sizeof(sctp_header_data) +sizeof(m3ua_header_data) + trinf->datalen + ppidlen);
	stcphedata->sid = 0;
	stcphedata->ppid = htonl(M3UA_ppid);

	//xie  m3ua
	m3ua_head->ver = 1;
	m3ua_head->res = 0;
	m3ua_head->cla = 1;
	m3ua_head->tpe = 1;
	
	m3ua_head->len = htonl(ppidlen + trinf->datalen + sizeof(m3ua_header_data));
	m3ua_head->tag = htons(0x0210);
	m3ua_head->parlen = htons(trinf->datalen + 16);
	if(trinf->flag == 1)
	{	
		m3ua_head->opc = htonl(stzm3uainfo[fileid].fir.OPC);
		m3ua_head->dpc = htonl(stzm3uainfo[fileid].sec.DPC);
	}
	else if(trinf->flag == 2)
	{
		m3ua_head->dpc = htonl(stzm3uainfo[fileid].fir.OPC);
		m3ua_head->opc = htonl(stzm3uainfo[fileid].sec.DPC);
	}
	m3ua_head->si =  3;
	m3ua_head->ni =  trinf->ni;
	m3ua_head->mp =  0;
	m3ua_head->sls = 0;
	if(stzm3uainfo[fileid].typeube == 0)
	{
		stcphead->checksum = htonl(Sctpchksum((U8 *)stcphedata,sizeof(sctp_header_data) + sizeof(m3ua_header_data) + trinf->datalen));
	}	

	else if(stzm3uainfo[fileid].typeube == TYPEUBE)
	{
		stcpheack->checksum = htonl(Sctpchksum((U8 *)stcphedata,sizeof(sctp_header_data) + sizeof(m3ua_header_data) + trinf->datalen));
	}
	
	fwrite(stcpbuf, stcphead_len+sizeof(sctp_header_data) + sizeof(m3ua_header_data) + trinf->datalen, 1, fp);

	
	uint8_t ppid_data[] = {	
	0x00, 0x00, 0x00, 0x00
	};
	fwrite(ppid_data, ppidlen, 1, fp);
	pthread_mutex_unlock(&mutex_file);
	//fclose(fp); 
	return 0;

}


void* worktotcpfile(void* arg)
{
	unsigned short flags = ((tostcpinfo*)arg)->flags;
	traninfo *trinf = &((tostcpinfo*)arg)->trinf;
	pkgtype type = ((tostcpinfo*)arg)->type;	
	//printf("work winfo\n\n");
	//printf("winfo:%d\n\n",flags);
	//printf("kinfo:%d\n\n",type);
	//printf("kinfo:%d\n\n",trinf->dport);
	//printf("kinfo:%d\n\n",trinf->sport);
	for(int i = 0; i < 16; ++i)
	{
		if(flags >> i & 0x01)
		{
			FILE *fp2 = NULL;
			char iswitefilehead;
			char tmpfilename[32] = "./pcap/";
			strcat(tmpfilename,(char *)evtrace2::get()->sztrace2[i+1].filename);
			if(access(tmpfilename,F_OK) != 0)
			{
				//pthread_mutex_lock(&mutex_file);
				iswitefilehead = 1;	
				//pthread_mutex_unlock(&mutex_file);
			}
			else
			{
				iswitefilehead = 0;	
			}
			fp2 = fopen(tmpfilename, "a+");  
		    if (!fp2){  
		        fprintf(stderr, "fopen %s for write failed. errno=%d desc=%s\n",   
		            tmpfilename, errno, strerror(errno));  
		        return NULL;  
		    }
			if(iswitefilehead == 1)
			{
				struct pcap_file_header hdr; 
			    hdr.magic = TCPDUMP_MAGIC;
			    hdr.version_major = PCAP_VERSION_MAJOR;
			    hdr.version_minor = PCAP_VERSION_MINOR;
			    hdr.thiszone = 0;
			    hdr.sigfigs  = 0;
			    hdr.snaplen  = 65535;
			    hdr.linktype = 113;
			    fwrite((char *)&hdr, sizeof(pcap_file_header), 1, fp2);
			}
			switch(type)
			{
				case PKG_TCP:
					totcppack(fp2,trinf,i+1);
					break;
				case PKG_STCP:
					tostcppack(fp2,trinf,i+1);
				case PKG_M3UA:
					//tom3uapack(fp2,trinf,i+1);
					break;
				default:
					break;
			}
			fclose(fp2);
		}
	}
	free(arg);
    return NULL;
}


void* worktom3uafile(void* arg)
{
	unsigned short flags = ((tom3uainfo*)arg)->flags;
	m3uainfo *trinf = &((tom3uainfo*)arg)->trinf;
	for(int i = 0; i < 16; ++i)
	{
		if(flags >> i & 0x01)
		{
			FILE *fp2 = NULL;
			char iswitefilehead;
			char tmpfilename[32] = "./pcap/";
			strcat(tmpfilename,(char *)evtrace2::get()->sztrace2[i+1].filename);
			if(access(tmpfilename,F_OK) != 0)
			{
				//printf("file:%s\n no find\n\n",tmpfilename);
				//pthread_mutex_lock(&mutex_file);
				iswitefilehead = 1;	
				//pthread_mutex_unlock(&mutex_file);
			}
			else
			{
				//printf("file:%s\n is find\n\n",tmpfilename);
				iswitefilehead = 0;	
			}
			fp2 = fopen(tmpfilename, "a+");  
		    if (!fp2){  
		        fprintf(stderr, "fopen %s for write failed. errno=%d desc=%s\n",   
		            tmpfilename, errno, strerror(errno));  
		        return NULL;  
		    }
			if(iswitefilehead == 1)
			{
				struct pcap_file_header hdr; 
			    hdr.magic = TCPDUMP_MAGIC;
			    hdr.version_major = PCAP_VERSION_MAJOR;
			    hdr.version_minor = PCAP_VERSION_MINOR;
			    hdr.thiszone = 0;
			    hdr.sigfigs  = 0;
			    hdr.snaplen  = 65535;
			    hdr.linktype = 113;
			    fwrite((char *)&hdr, sizeof(pcap_file_header), 1, fp2);
			}
			tom3uapack(fp2,trinf,i+1);
			fclose(fp2);
		}
	}
	free(arg);
    return NULL;
}

static int istcpinit;
static struct threadpool *tcppool;
static int ism3uainit;
static struct threadpool *m3uapool;

int write_tcppkg(unsigned short flags,traninfo *trinf, pkgtype type)
{
	mkdir("pcap/", 0755);
	tostcpinfo *tcpinfo = (tostcpinfo *)malloc(sizeof(tostcpinfo));
	tcpinfo->flags = flags;
	if(NULL != trinf)
	memcpy(&tcpinfo->trinf,trinf,sizeof(traninfo));
	tcpinfo->type = type;
	if(istcpinit == 0)
	{
		tcppool = threadpool_init(10, 20);
		istcpinit = 1;
	}
	threadpool_add_job(tcppool, worktotcpfile, (void*)tcpinfo);
	return 0;
}

int write_m3uapkg(unsigned short flags,m3uainfo *trinf)
{
	mkdir("pcap/", 0755);
	tom3uainfo *mtpinfo = (tom3uainfo *)malloc(sizeof(tom3uainfo));
	mtpinfo->flags = flags;
	if(NULL != trinf)
	memcpy(&mtpinfo->trinf,trinf,sizeof(m3uainfo));

	if(ism3uainit == 0)
	{
		m3uapool = threadpool_init(10, 20);
		ism3uainit = 1;
	}
	threadpool_add_job(m3uapool, worktom3uafile, (void*)mtpinfo);
	return 0;
}


int write_pkdata(U16 flags,U8 *data, U16 datalen)
{
	for(int i = 0; i < 16; ++i)
	{
		if(flags >> i & 0x01)
		{
			FILE *fp2 = NULL;
			char iswitefilehead;
			if(access((char *)evtrace2::get()->sztrace2[i+1].filename,F_OK) != 0)
			{
				iswitefilehead = 1;	
			}
			else
			{
				iswitefilehead = 0;	
			}
			fp2 = fopen((char *)evtrace2::get()->sztrace2[i+1].filename, "a+");  
		    if (!fp2){  
		        fprintf(stderr, "fopen %s for write failed. errno=%d desc=%s\n",   
		            (char *)evtrace2::get()->sztrace2[i+1].filename, errno, strerror(errno));  
		        return NULL;  
		    }
			if(iswitefilehead == 1)
			{
				struct pcap_file_header hdr; 
			    hdr.magic = TCPDUMP_MAGIC;
			    hdr.version_major = PCAP_VERSION_MAJOR;
			    hdr.version_minor = PCAP_VERSION_MINOR;
			    hdr.thiszone = 0;
			    hdr.sigfigs  = 0;
			    hdr.snaplen  = 65535;
			    hdr.linktype = 113;
			    fwrite((char *)&hdr, sizeof(pcap_file_header), 1, fp2);
			}
			fwrite(data, datalen, 1, fp2);
			fclose(fp2);
		}
	}
}

struct threadpool* threadpool_init(int thread_num, int queue_max_num)
{
    struct threadpool *pool = NULL;
    do 
    {
        pool = (threadpool *)malloc(sizeof(struct threadpool));
        if (NULL == pool)
        {
            printf("failed to malloc threadpool!\n");
            break;
        }
        pool->thread_num = thread_num;
        pool->queue_max_num = queue_max_num;
        pool->queue_cur_num = 0;
        pool->head = NULL;
        pool->tail = NULL;
        if (pthread_mutex_init(&(pool->mutex), NULL))
        {
            printf("failed to init mutex!\n");
            break;
        }
        if (pthread_cond_init(&(pool->queue_empty), NULL))
        {
            printf("failed to init queue_empty!\n");
            break;
        }
        if (pthread_cond_init(&(pool->queue_not_empty), NULL))
        {
            printf("failed to init queue_not_empty!\n");
            break;
        }
        if (pthread_cond_init(&(pool->queue_not_full), NULL))
        {
            printf("failed to init queue_not_full!\n");
            break;
        }
        pool->pthreads = (pthread_t *)malloc(sizeof(pthread_t) * thread_num);
        if (NULL == pool->pthreads)
        {
            printf("failed to malloc pthreads!\n");
            break;
        }
        pool->queue_close = 0;
        pool->pool_close = 0;
        int i;
        for (i = 0; i < pool->thread_num; ++i)
        {
            pthread_create(&(pool->pthreads[i]), NULL, threadpool_function, (void *)pool);
        }
        
        return pool;    
    } while (0);
    
    return NULL;
}

int threadpool_add_job(struct threadpool* pool, void* (*callback_function)(void *arg), void *arg)
{
    assert(pool != NULL);
    assert(callback_function != NULL);
    assert(arg != NULL);

    pthread_mutex_lock(&(pool->mutex));
    while ((pool->queue_cur_num == pool->queue_max_num) && !(pool->queue_close || pool->pool_close))
    {
        pthread_cond_wait(&(pool->queue_not_full), &(pool->mutex));   //队列满的时候就等待
    }
    if (pool->queue_close || pool->pool_close)    //队列关闭或者线程池关闭就退出
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    }
    struct job *pjob =(struct job*) malloc(sizeof(struct job));
    if (NULL == pjob)
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    } 
    pjob->callback_function = callback_function;    
    pjob->arg = arg;

	
    pjob->next = NULL;
    if (pool->head == NULL)   
    {
        pool->head = pool->tail = pjob;
        pthread_cond_broadcast(&(pool->queue_not_empty));  //队列空的时候，有任务来时就通知线程池中的线程：队列非空
    }
    else
    {
        pool->tail->next = pjob;
        pool->tail = pjob;    
    }
    pool->queue_cur_num++;
    pthread_mutex_unlock(&(pool->mutex));
    return 0;
}

void* threadpool_function(void* arg)
{
    struct threadpool *pool = (struct threadpool*)arg;
    struct job *pjob = NULL;
    while (1)  //死循环
    {
        pthread_mutex_lock(&(pool->mutex));
        while ((pool->queue_cur_num == 0) && !pool->pool_close)   //队列为空时，就等待队列非空
        {
            pthread_cond_wait(&(pool->queue_not_empty), &(pool->mutex));
        }
        if (pool->pool_close)   //线程池关闭，线程就退出
        {
            pthread_mutex_unlock(&(pool->mutex));
            pthread_exit(NULL);
        }
        pool->queue_cur_num--;
        pjob = pool->head;
        if (pool->queue_cur_num == 0)
        {
            pool->head = pool->tail = NULL;
        }
        else 
        {
            pool->head = pjob->next;
        }
        if (pool->queue_cur_num == 0)
        {
            pthread_cond_signal(&(pool->queue_empty));        //队列为空，就可以通知threadpool_destroy函数，销毁线程函数
        }
        if (pool->queue_cur_num == pool->queue_max_num - 1)
        {
            pthread_cond_broadcast(&(pool->queue_not_full));  //队列非满，就可以通知threadpool_add_job函数，添加新任务
        }
        pthread_mutex_unlock(&(pool->mutex));
        (*(pjob->callback_function))(pjob->arg);   //线程真正要做的工作，回调函数的调用
        free(pjob);
        pjob = NULL;    
    }
}
int threadpool_destroy(struct threadpool *pool)
{
    assert(pool != NULL);
    pthread_mutex_lock(&(pool->mutex));
    if (pool->queue_close || pool->pool_close)   //线程池已经退出了，就直接返回
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    }
    
    pool->queue_close = 1;        //置队列关闭标志
    while (pool->queue_cur_num != 0)
    {
        pthread_cond_wait(&(pool->queue_empty), &(pool->mutex));  //等待队列为空
    }    
    
    pool->pool_close = 1;      //置线程池关闭标志
    pthread_mutex_unlock(&(pool->mutex));
    pthread_cond_broadcast(&(pool->queue_not_empty));  //唤醒线程池中正在阻塞的线程
    pthread_cond_broadcast(&(pool->queue_not_full));   //唤醒添加任务的threadpool_add_job函数
    int i;
    for (i = 0; i < pool->thread_num; ++i)
    {
        pthread_join(pool->pthreads[i], NULL);    //等待线程池的所有线程执行完毕
    }
    
    pthread_mutex_destroy(&(pool->mutex));          //清理资源
    pthread_cond_destroy(&(pool->queue_empty));
    pthread_cond_destroy(&(pool->queue_not_empty));   
    pthread_cond_destroy(&(pool->queue_not_full));    
    free(pool->pthreads);
    struct job *p;
    while (pool->head != NULL)
    {
        p = pool->head;
        pool->head = p->next;
        free(p);
    }
    free(pool);
    return 0;
}

#if 0
int test(FILE *fp)
{
	struct pcap_file_header hdr; 
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs  = 0;
    hdr.snaplen  = 65535;
    hdr.linktype = 113;
    fwrite((char *)&hdr, sizeof(pcap_file_header), 1, fp);

    unsigned int h[4]; 
    struct timeval tv;
    gettimeofday(&tv, NULL);  
    h[0] = (unsigned int)tv.tv_sec;
    h[1] = (unsigned int)tv.tv_usec;
    h[2] = 228;
    h[3] = 228;
    fwrite((char *)&h, sizeof(h), 1, fp);
 	fwrite(mac_data, 16, 1, fp);
//填充IP
   struct iphdr iphead;
   iphead.version = 4;//版本号
   iphead.ihl = 5;
   iphead.tos = 0;
   iphead.tot_len = htons(20+32+160);//整个数据报总长度
   iphead.id = 13;
   iphead.frag_off = 0x40;//不分段
   iphead.ttl = 255;
   iphead.protocol = IPPROTO_TCP;
   iphead.check = 0;
   iphead.saddr = inet_addr("192.168.1.49");//这里IP只是一个代号
   iphead.daddr = inet_addr("192.168.1.246");
   fwrite((char *)&iphead, sizeof(iphead), 1, fp);
//填充TCP
	char tcpbuf[1024];
    memset(tcpbuf, '\0', 1024);
    struct psd * psd = (struct psd *)tcpbuf; //伪头部 = 12字节
    struct tcphdr *tcphead = (struct tcphdr *)(tcpbuf+12); 
    memcpy(tcpbuf+12+32,smgp_data,160);
//伪头部 
    psd->src.s_addr = inet_addr("192.168.1.49"); //源地址
    psd->dst.s_addr = inet_addr("192.168.1.246");
    psd->p = 6;
    psd->zero = 0;
    psd->len = htons(32+160);  //TCP数据包 = 64字节
	tcphead->source = htons(12);
	tcphead->dest = htons(34);
	tcphead->seq = htons(0);
	tcphead->ack_seq = htons(0);
    tcphead->doff = 8;  //TCP头部 = 5*4 = 20字节
    tcphead->psh = 1;
    tcphead->ack = 1;
    tcphead->window = htons(1024);
    tcphead->check = htons(chksum((unsigned char *)tcpbuf, 12+32+160)); //伪头部 + TCP数据包 = 76字节
    fwrite(tcpbuf+12, 32+160, 1, fp);
}   
#endif
