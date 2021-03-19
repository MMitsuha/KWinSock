#include "WskSocket.h"
#include "HTTP_Parser/http_parser.h"
#include "MD5.h"
#include <minwindef.h>
#include <string.h>
#define _NO_CRT_STDIO_INLINE
#include <ntstrsafe.h>

#define DebuggerPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__);
#define KWS_MEM_TAG ' SWK'

#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)

//#define FILE_PATH L"\\??\\C:\\mitusha.jpg"
//
//#define HOST_PATH "p.pstatp.com"
//#define LHOST_PATH L"p.pstatp.com"

#define FILE_PATH L"\\??\\C:\\sysdiag-full-5.0.58.2-20210313.exe"

#define HOST_ROOT "down5.huorong.cn"
#define LHOST_ROOT L"down5.huorong.cn"

#define HOST_FILE_PATH "/sysdiag-full-5.0.58.2-20210313.exe"

//int
//onURL(
//	http_parser* _,
//	const char* at,
//	size_t length
//)
//{
//	DebuggerPrint("%s\n", at);
//	return 0;
//}

typedef struct _USER_DATA
{
	HANDLE hFile;
}USER_DATA, * PUSER_DATA;

char* LastData = NULL;
size_t LastLength = 0;

int
onChunkHeader(
	http_parser* pparser
)
{
	DebuggerPrint("[KS] %S Chunk length:%I64u\n", __FUNCTIONW__, pparser->content_length);

	return 0;
}

int
onChunkComplete(
	http_parser* _
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onStatus(
	http_parser* _,
	const char* at,
	size_t length
)
{
	DebuggerPrint("[KS] %S:%.*s\n", __FUNCTIONW__, (ULONG)length, at);

	return 0;
}

int
onHeaderField(
	http_parser* _,
	const char* at,
	size_t length
)
{
	//DebuggerPrint("[KS] %S:%.*s\n", __FUNCTIONW__, (ULONG)length, at);

	LastData = ExAllocatePoolWithTag(PagedPool, length, KWS_MEM_TAG);
	if (LastData)
	{
		RtlCopyMemory(LastData, at, length);
		LastLength = length;
	}

	return 0;
}

int
onHeaderValue(
	http_parser* _,
	const char* at,
	size_t length
)
{
	if (LastLength != 0 && LastData)
	{
		DebuggerPrint("[KS] %S:%.*s:%.*s\n", __FUNCTIONW__, (ULONG)LastLength, LastData, (ULONG)length, at);
		ExFreePoolWithTag(LastData, KWS_MEM_TAG);
	}

	LastData = NULL;
	LastLength = 0;

	return 0;
}

int
onBody(
	http_parser* pparser,
	const char* at,
	size_t length
)
{
	//DebuggerPrint("[KS] %S:%.*s\n", __FUNCTIONW__, (ULONG)length, at);

	IO_STATUS_BLOCK IoStatus = { 0 };
	NTSTATUS ntStatus = ZwWriteFile(((PUSER_DATA)pparser->data)->hFile, NULL, NULL, NULL, &IoStatus, (PVOID)at, length, NULL, NULL);
	if (!NT_SUCCESS(ntStatus))
		;

	return 0;
}

int
onMessageBegin(
	http_parser* _
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onMessageComplete(
	http_parser* _
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onHeadersComplete(
	http_parser* _
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

NTSTATUS
NTAPI
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS ntStatus;

	//
	// Initialize KSOCKET.
	//

	ntStatus = KsInitialize();

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

#if _CLIENT_MODE
	//
	// Client.
	//

	{
		HANDLE hFile = NULL;
		UNICODE_STRING FileName = RTL_CONSTANT_STRING(FILE_PATH);
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
		IO_STATUS_BLOCK IoStatus = { 0 };
		// 以OPEN_IF方式打开文件。
		ntStatus = ZwCreateFile(
			&hFile,
			GENERIC_WRITE,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE |
			FILE_RANDOM_ACCESS |
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (NT_SUCCESS(ntStatus))
		{
			BYTE SendBuffer[] = "GET "HOST_FILE_PATH" HTTP/1.1\r\n"
				"Connection:Close\r\n"
				"Accept-Encoding:\r\n"
				"Accept-Charset:utf-8\r\n"
				"Accept-Language:zh-CN,en,*\r\n"
				"host:"HOST_ROOT"\r\n"
				"User-Agent:Mozilla/5.0\r\n\r\n";

			BYTE RecvBuffer[1025] = { 0 };

			/* struct addrinfo* res;
			 result = getaddrinfo("www.baidu.com", "80", &hints, &res);*/

			ADDRINFOEXW Hints = { 0 };
			Hints.ai_flags |= AI_CANONNAME;
			Hints.ai_family = AF_UNSPEC;
			Hints.ai_socktype = SOCK_STREAM;
			UNICODE_STRING NodeName = RTL_CONSTANT_STRING(LHOST_ROOT);
			UNICODE_STRING Port = RTL_CONSTANT_STRING(L"80");
			PADDRINFOEXW Result = { 0 };
			ntStatus = KsGetAddrInfo(&NodeName, &Port, &Hints, &Result);
			if (NT_SUCCESS(ntStatus))
			{
				//DebuggerPrint("%S\n", Result->ai_canonname);

				PKSOCKET Socket = NULL;
				ntStatus = KsCreateConnectionSocket(&Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if (NT_SUCCESS(ntStatus))
				{
					http_parser_settings settings = { 0 };
					settings.on_message_begin = onMessageBegin;
					settings.on_message_complete = onMessageComplete;
					settings.on_status = onStatus;
					settings.on_body = onBody;
					settings.on_chunk_complete = onChunkComplete;
					settings.on_chunk_header = onChunkHeader;
					settings.on_headers_complete = onHeadersComplete;
					settings.on_header_field = onHeaderField;
					settings.on_header_value = onHeaderValue;
					/* ... */

					USER_DATA UserData = { 0 };
					UserData.hFile = hFile;

					http_parser parser = { 0 };
					http_parser_init(&parser, HTTP_RESPONSE);
					parser.data = &UserData;

					ntStatus = KsConnect(Socket, Result->ai_addr);
					if (NT_SUCCESS(ntStatus))
					{
						ULONG Length = 0;
						ntStatus = KsSend(Socket, SendBuffer, sizeof(SendBuffer), 0, &Length);
						DebuggerPrint("[KS] Send:%u\n", Length);
						if (NT_SUCCESS(ntStatus))
						{
							/*BOOLEAN FoundHeader = FALSE;*/

							while (TRUE)
							{
								Length = 0;
								ntStatus = KsRecv(Socket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);
								if (!NT_SUCCESS(ntStatus) || !Length)
									break;

								RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])] = 0;
								RecvBuffer[Length] = 0;

								if (http_parser_execute(&parser, &settings, RecvBuffer, Length) != Length)
								{
									ntStatus = STATUS_UNSUCCESSFUL;
									break;
								}

								/*PCHAR Ret = NULL;
								if (!FoundHeader)
								{
									Ret = strstr(RecvBuffer, "\r\n\r\n");
									if (Ret != NULL)
									{
										Ret += 4;
										FoundHeader = TRUE;
									}
								}

								if (!Ret)
									Ret = RecvBuffer;

								if (FoundHeader)
								{
									ntStatus = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, Ret, Length - (ULONG)(Ret - RecvBuffer), NULL, NULL);
									if (!NT_SUCCESS(ntStatus))
										break;
								}*/
							}
						}
					}

					KsCloseSocket(Socket);
				}

				KsFreeAddrInfo(Result);
			}

			ZwClose(hFile);
		}
	}
#else
	//
	// TCP server.
	// Listen on port 9095, wait for some message,
	// then send our buffer and close connection.
	//
	// Try:
	// > nc 127.0.0.1 9095 [enter]
	// > HELLO FROM USERMODE! [enter]
	// > Hello from WSK! [expected response]
	//

	{
		PKSOCKET Socket = NULL;
		ntStatus = KsCreateListenSocket(&Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (NT_SUCCESS(ntStatus))
		{
			SOCKADDR_IN SockAddr = { 0 };
			SockAddr.sin_addr.s_addr = INADDR_ANY;
			SockAddr.sin_family = AF_INET;
			SockAddr.sin_port = htons(9095);
			ntStatus = KsBind(Socket, (PSOCKADDR)&SockAddr);
			if (NT_SUCCESS(ntStatus))
			{
				PKSOCKET ListenSocket = NULL;
				ntStatus = KsAccept(Socket, &ListenSocket, NULL, (PSOCKADDR)&SockAddr);
				if (NT_SUCCESS(ntStatus))
				{
					BYTE RecvBuffer[1025] = { 0 };
					ULONG Length = 0;
					while (TRUE)
					{
						Length = 0;
						KsRecv(ListenSocket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);
						if (!NT_SUCCESS(ntStatus) || !Length)
							break;

						RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])] = 0;
						RecvBuffer[Length] = 0;

						DebuggerPrint("%s", RecvBuffer);

						if (!strncmp(RecvBuffer, "exit\n", Length))
							break;

						BYTE MD5Str[MD5_STR_LEN] = { 0 };
						BYTE MD5Value[MD5_SIZE] = { 0 };
						MD5_CTX Context = { 0 };
						MD5Init(&Context);
						MD5Update(&Context, RecvBuffer, Length);
						MD5Final(&Context, MD5Value);

						for (BYTE i = 0; i < MD5_SIZE; i++)
							RtlStringCbPrintfA(&MD5Str[i * 2], 2 + 1, "%02x", MD5Value[i]);

						DebuggerPrint("%s\n", MD5Str);
					}

					KsCloseSocket(ListenSocket);
				}
			}

			KsCloseSocket(Socket);
		}
	}
#endif

	//
	// Destroy KSOCKET.
	//

	KsDestroy();

	//
	// Unload the driver immediately.
	//

	return STATUS_UNSUCCESSFUL;
}