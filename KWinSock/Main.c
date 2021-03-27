#define _CLIENT_MODE 1
#define USING_HTTP_PARSER 0

#include "WskSocket.h"
#if USING_HTTP_PARSER
#include "HTTP_Parser/include/http_parser.h"
#else
#include "llhttp/include/llhttp.h"
#endif
#include "MD5.h"
#include <minwindef.h>
#include <string.h>
#include <intrin.h>
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
#if USING_HTTP_PARSER
	http_parser* pparser
#else
	llhttp_t* pparser
#endif
)
{
	DebuggerPrint("[KS] %S Chunk length:%I64u\n", __FUNCTIONW__, pparser->content_length);

	return 0;
}

int
onChunkComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onStatus(
#if USING_HTTP_PARSER
	http_parser* _,
#else
	llhttp_t* _,
#endif
	const char* at,
	size_t length
)
{
	DebuggerPrint("[KS] %S:%.*s\n", __FUNCTIONW__, (ULONG)length, at);

	return 0;
}

int
onHeaderField(
#if USING_HTTP_PARSER
	http_parser* _,
#else
	llhttp_t* _,
#endif
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
#if USING_HTTP_PARSER
	http_parser* _,
#else
	llhttp_t* _,
#endif
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

UINT64 TotalLength = 0;

int
onBody(
#if USING_HTTP_PARSER
	http_parser* pparser,
#else
	llhttp_t* pparser,
#endif
	const char* at,
	size_t length
)
{
	//DebuggerPrint("[KS] %S:%.*s\n", __FUNCTIONW__, (ULONG)length, at);
	TotalLength += length;

	IO_STATUS_BLOCK IoStatus = { 0 };
	NTSTATUS ntStatus = ZwWriteFile(((PUSER_DATA)pparser->data)->hFile, NULL, NULL, NULL, &IoStatus, (PVOID)at, length, NULL, NULL);
	if (!NT_SUCCESS(ntStatus))
		;

	return 0;
}

int
onMessageBegin(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onMessageComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onHeadersComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

#if !USING_HTTP_PARSER
int
onStatusComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onHeaderFieldComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}

int
onHeaderValueComplete(
#if USING_HTTP_PARSER
	http_parser* _
#else
	llhttp_t* _
#endif
)
{
	DebuggerPrint("[KS] %S\n", __FUNCTIONW__);

	return 0;
}
#endif

ULONG g_uNumberOfRaisedCPU = 0;
ULONG g_uAllCPURaised = 0;
PKDPC g_basePKDPC = NULL;

VOID
RaiseCPUIrqlAndWait(
	IN PKDPC Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(Dpc);

	InterlockedIncrement((PLONG)&g_uNumberOfRaisedCPU);
	while (!InterlockedCompareExchange((PLONG)&g_uAllCPURaised, 1, 1))
		__nop();

	InterlockedDecrement((PLONG)&g_uNumberOfRaisedCPU);
}

VOID
ReleaseExclusivity(
	VOID
)
{
	InterlockedIncrement((PLONG)&g_uAllCPURaised);
	while (InterlockedCompareExchange((PLONG)&g_uNumberOfRaisedCPU, 0, 0))
		__nop();

	if (NULL != g_basePKDPC)
	{
		ExFreePool((PVOID)g_basePKDPC);
		g_basePKDPC = NULL;
	}

	return;
}

BOOLEAN
GainExlusivity(
	VOID
)
{
	ULONG uCurrentCpu = 0;
	PKDPC tempDpc = NULL;
	if ((DISPATCH_LEVEL != KeGetCurrentIrql()) || !KeNumberProcessors)
		return FALSE;

	InterlockedAnd((PLONG)&g_uNumberOfRaisedCPU, 0);
	InterlockedAnd((PLONG)&g_uAllCPURaised, 0);
	tempDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors * sizeof(KDPC), KWS_MEM_TAG);
	if (tempDpc)
	{
		g_basePKDPC = tempDpc;
		uCurrentCpu = KeGetCurrentProcessorNumber();
		for (ULONG i = 0; i < (ULONG)KeNumberProcessors; i++, *tempDpc++)
			if (i != uCurrentCpu)
			{
				KeInitializeDpc(tempDpc, RaiseCPUIrqlAndWait, NULL);
				KeSetTargetProcessorDpc(tempDpc, (CCHAR)i);
				KeInsertQueueDpc(tempDpc, NULL, NULL);
			}

		while (KeNumberProcessors - 1 != InterlockedCompareExchange((PLONG)&g_uNumberOfRaisedCPU, KeNumberProcessors - 1, KeNumberProcessors - 1))
			__nop();

		return TRUE;
	}

	return FALSE;
}

#define BV_COLOR_BLACK          0
#define BV_COLOR_RED            1
#define BV_COLOR_GREEN          2
#define BV_COLOR_BROWN          3
#define BV_COLOR_BLUE           4
#define BV_COLOR_MAGENTA        5
#define BV_COLOR_CYAN           6
#define BV_COLOR_DARK_GRAY      7
#define BV_COLOR_LIGHT_GRAY     8
#define BV_COLOR_LIGHT_RED      9
#define BV_COLOR_LIGHT_GREEN    10
#define BV_COLOR_YELLOW         11
#define BV_COLOR_LIGHT_BLUE     12
#define BV_COLOR_LIGHT_MAGENTA  13
#define BV_COLOR_LIGHT_CYAN     14
#define BV_COLOR_WHITE          15
#define BV_COLOR_NONE           16
#define BV_MAX_COLORS           16

#define VGA_CHAR_SIZE 2

#define TEXT_CHAR_SIZE 2

#define CHAR_WIDTH  8
#define CHAR_HEIGHT 16

#define SCREEN_WIDTH  640
#define SCREEN_HEIGHT 400
#define BYTES_PER_SCANLINE (SCREEN_WIDTH / 8)

typedef enum _INBV_DISPLAY_STATE
{
	INBV_DISPLAY_STATE_OWNED,     // we own the display
	INBV_DISPLAY_STATE_DISABLED,  // we own but should not use
	INBV_DISPLAY_STATE_LOST       // we lost ownership
} INBV_DISPLAY_STATE;

typedef
BOOLEAN
(*INBV_RESET_DISPLAY_PARAMETERS)(
	ULONG Cols,
	ULONG Rows
	);

typedef
VOID
(*INBV_DISPLAY_STRING_FILTER)(
	PUCHAR* Str
	);

NTKERNELAPI
VOID
InbvNotifyDisplayOwnershipLost(
	INBV_RESET_DISPLAY_PARAMETERS ResetDisplayParameters
);

NTKERNELAPI
VOID
InbvInstallDisplayStringFilter(
	INBV_DISPLAY_STRING_FILTER DisplayStringFilter
);

NTKERNELAPI
VOID
InbvAcquireDisplayOwnership(
	VOID
);

BOOLEAN
InbvDriverInitialize(
	IN PVOID LoaderBlock,
	IN ULONG Count
);

NTKERNELAPI
BOOLEAN
InbvResetDisplay(
);

VOID
InbvBitBlt(
	PUCHAR Buffer,
	ULONG x,
	ULONG y
);

NTKERNELAPI
VOID
InbvSolidColorFill(
	ULONG x1,
	ULONG y1,
	ULONG x2,
	ULONG y2,
	ULONG color
);

NTKERNELAPI
BOOLEAN
InbvDisplayString(
	PUCHAR Str
);

VOID
InbvUpdateProgressBar(
	ULONG Percentage
);

VOID
InbvSetProgressBarSubset(
	ULONG   Floor,
	ULONG   Ceiling
);

VOID
InbvSetBootDriverBehavior(
	PVOID LoaderBlock
);

VOID
InbvIndicateProgress(
	VOID
);

VOID
InbvSetProgressBarCoordinates(
	ULONG x,
	ULONG y
);

NTKERNELAPI
VOID
InbvEnableBootDriver(
	BOOLEAN bEnable
);

NTKERNELAPI
BOOLEAN
InbvEnableDisplayString(
	BOOLEAN bEnable
);

NTKERNELAPI
BOOLEAN
InbvIsBootDriverInstalled(
	VOID
);

PUCHAR
InbvGetResourceAddress(
	IN ULONG ResourceNumber
);

VOID
InbvBufferToScreenBlt(
	PUCHAR Buffer,
	ULONG x,
	ULONG y,
	ULONG width,
	ULONG height,
	ULONG lDelta
);

VOID
InbvScreenToBufferBlt(
	PUCHAR Buffer,
	ULONG x,
	ULONG y,
	ULONG width,
	ULONG height,
	ULONG lDelta
);

BOOLEAN
InbvTestLock(
	VOID
);

VOID
InbvAcquireLock(
	VOID
);

VOID
InbvReleaseLock(
	VOID
);

NTKERNELAPI
BOOLEAN
InbvCheckDisplayOwnership(
	VOID
);

NTKERNELAPI
VOID
InbvSetScrollRegion(
	ULONG x1,
	ULONG y1,
	ULONG x2,
	ULONG y2
);

NTKERNELAPI
ULONG
InbvSetTextColor(
	ULONG Color
);

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
#if USING_HTTP_PARSER
					http_parser_settings settings = { 0 };
					http_parser_settings_init(&settings);
#else
					llhttp_settings_t settings = { 0 };
					llhttp_settings_init(&settings);
					settings.on_status_complete = onStatusComplete;
					settings.on_header_field_complete = onHeaderFieldComplete;
					settings.on_header_value_complete = onHeaderValueComplete;
#endif
					settings.on_message_begin = onMessageBegin;
					settings.on_status = onStatus;
					settings.on_header_field = onHeaderField;
					settings.on_header_value = onHeaderValue;
					settings.on_headers_complete = onHeadersComplete;
					settings.on_body = onBody;
					settings.on_message_complete = onMessageComplete;
					settings.on_chunk_header = onChunkHeader;
					settings.on_chunk_complete = onChunkComplete;
					/* ... */

					USER_DATA UserData = { 0 };
					UserData.hFile = hFile;

#if USING_HTTP_PARSER
					http_parser parser = { 0 };
					http_parser_init(&parser, HTTP_RESPONSE);
#else
					llhttp_t parser = { 0 };
					llhttp_init(&parser, HTTP_RESPONSE, &settings);
#endif
					parser.data = &UserData;

					ntStatus = KsConnect(Socket, Result->ai_addr);
					if (NT_SUCCESS(ntStatus))
					{
						ULONG Length = 0;
						ntStatus = KsSend(Socket, SendBuffer, sizeof(SendBuffer), 0, &Length);
						DebuggerPrint("[KS] Send:%u\n", Length);
						if (NT_SUCCESS(ntStatus))
						{
							DebuggerPrint("-----START-----\n");
							/*BOOLEAN FoundHeader = FALSE;*/

							while (TRUE)
							{
								Length = 0;
								ntStatus = KsRecv(Socket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);
								if (!NT_SUCCESS(ntStatus) || !Length)
									break;

								RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])] = 0;
								RecvBuffer[Length] = 0;

#if USING_HTTP_PARSER
								if (http_parser_execute(&parser, &settings, RecvBuffer, Length) != Length)
								{
									ntStatus = STATUS_UNSUCCESSFUL;
									break;
								}
#else
								enum llhttp_errno err = llhttp_execute(&parser, RecvBuffer, Length);
								if (err != HPE_OK)
								{
									ntStatus = STATUS_UNSUCCESSFUL;
									break;
								}
#endif

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

							DebuggerPrint("-----END-----\n");
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
	//
	// Try:
	// > nc 127.0.0.1 9095 [enter]
	// > HELLO FROM USERMODE! [enter]
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
						ntStatus = KsRecv(ListenSocket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);
						if (!NT_SUCCESS(ntStatus) || !Length)
							break;

						RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])] = 0;
						RecvBuffer[Length] = 0;

						if (!strncmp(RecvBuffer, "exit\n", Length))
							break;

						DebuggerPrint("%s", RecvBuffer);

						BYTE MD5Str[MD5_STR_LEN] = { 0 };
						BYTE MD5Value[MD5_SIZE] = { 0 };
						MD5_CTX Context = { 0 };
						MD5Init(&Context);
						MD5Update(&Context, RecvBuffer, Length);
						MD5Final(&Context, MD5Value);

						for (BYTE i = 0; i < MD5_SIZE; i++)
							RtlStringCbPrintfA(&MD5Str[i * 2], 2 + 1, "%02X", MD5Value[i]);

						DebuggerPrint("%s\n", MD5Str);

						static CONST CHAR LF = '\n';
						KsSend(ListenSocket, MD5Str, sizeof(MD5Str), 0, NULL);
						KsSend(ListenSocket, &LF, sizeof(LF), 0, NULL);

						//_disable();
						//GainExlusivity();
						//KIRQL Irql = KeRaiseIrqlToDpcLevel();

						//if (InbvIsBootDriverInstalled())
						//{
						//	InbvAcquireDisplayOwnership();
						//	InbvResetDisplay();

						//	InbvSolidColorFill(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, MD5Value[0] % BV_MAX_COLORS);

						//	InbvSetTextColor(BV_COLOR_WHITE);
						//	InbvInstallDisplayStringFilter(NULL);
						//	InbvEnableDisplayString(TRUE);
						//	InbvSetScrollRegion(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1);
						//}

						//CHAR Text1[] = "Virus by Mitsuha & gt428 & TSK fxxked your computer so you got a strange CSoD.";
						//CHAR Text2[] = "Please SANLIAN TOUBI GUANZHU!";

						//for (SHORT j = 0; j < SCREEN_HEIGHT / CHAR_HEIGHT / 2; InterlockedIncrement16(&j))
						//{
						//	for (SHORT i = 0; i < (SCREEN_WIDTH / CHAR_WIDTH - sizeof(Text1) + 1) / 2; InterlockedIncrement16(&i))
						//		InbvDisplayString((PUCHAR)" ");
						//	InbvDisplayString((PUCHAR)Text1);
						//	InbvDisplayString((PUCHAR)"\r\n");

						//	for (SHORT i = 0; i < (SCREEN_WIDTH / CHAR_WIDTH - sizeof(Text2) + 1) / 2; InterlockedIncrement16(&i))
						//		InbvDisplayString((PUCHAR)" ");
						//	InbvDisplayString((PUCHAR)Text2);
						//	InbvDisplayString((PUCHAR)"\r\n");
						//}

						///*while (TRUE)
						//	;*/

						//KeLowerIrql(Irql);
						//ReleaseExclusivity();
						//_enable();
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