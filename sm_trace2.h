 
#include <stdio.h>
#include <string>
#include <vector>
#include <map>

using namespace std;
typedef unsigned char   U8;
typedef unsigned short  U16;
typedef unsigned int    U32;
typedef unsigned long   U64;

// get ip port
struct sbe
{
	unsigned int		id;
	unsigned int		rip;
	unsigned int		lip;
	unsigned short		rport;
	unsigned short		lport;
};

struct traninfo
{
	// TCP or SCTP
    unsigned int   sip;
    unsigned int   dip;
    unsigned short sport;
    unsigned short dport;
    unsigned int   datalen;
    unsigned char  data[1024];
};
struct m3uainfo
{
	U8    flag;
	U8    ni;
	U32   datalen;
    U8    data[1024];
};

struct smtrace2
{
	unsigned char 	id;
	unsigned char   enb;
	unsigned char   oa[22];
	unsigned char   da[22];
	unsigned char	pp_lnk;
	unsigned char	gp_lnk;
	unsigned char	map_cap;
	unsigned char   sccp_gt[22];
	unsigned char   filename[16];
};

enum pkgtype
{
	PKG_MIN,
	PKG_TCP,
	PKG_STCP,
	PKG_M3UA,
	PKG_MAX
};

class evtrace2
{
public:	
	static evtrace2* get()
	{
		static evtrace2 cx;
		return &cx;
	}
	int readtrace2();
	void show();

	int add(smtrace2 oc);
	int del(int id);
	smtrace2* get(int id);

	smtrace2 sztrace2[17];
	
	~evtrace2(){};
protected:
	
protected:	
	evtrace2(){};
};

unsigned short isnbr_trace2(char* oa, char* da);
unsigned short islnk_trace2(char pr, char lnk);
unsigned short isgt_trace2(char* gt);
int has_nbr_trace2();
int has_gt_trace2();
traninfo getsbeinfo(char pr,int lnk, char flag);
int write_pkdata(U16 flags,U8 *data, U16 datalen);
int write_tcppkg(unsigned short flags,traninfo *trinf, pkgtype type);
int write_m3uapkg(unsigned short flags,m3uainfo *trinf);


