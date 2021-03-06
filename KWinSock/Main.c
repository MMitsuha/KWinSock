#include "WskSocket.h"
#include <minwindef.h>
#include <string.h>

#define DebuggerPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__);

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

	//
	// Client.
	// Perform HTTP request to http://httpbin.org/uuid
	//

	{
		HANDLE hFile = NULL;
		UNICODE_STRING FileName = RTL_CONSTANT_STRING(L"\\??\\C:\\mitusha.jpg");
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
			BYTE SendBuffer[] = "GET /origin/137250002a438b83aa538 HTTP/1.1\r\n"
				"Connection:Close\r\n"
				"Accept-Encoding:\r\n"
				"Accept-Charset:utf-8\r\n"
				"Accept-Language:zh-CN,en,*\r\n"
				"host:p.pstatp.com\r\n"
				"User-Agent:Mozilla/5.0\r\n\r\n";

			BYTE RecvBuffer[1025] = { 0 };

			/* struct addrinfo* res;
			 result = getaddrinfo("www.baidu.com", "80", &hints, &res);*/

			ADDRINFOEXW Hints = { 0 };
			Hints.ai_flags |= AI_CANONNAME;
			Hints.ai_family = AF_UNSPEC;
			Hints.ai_socktype = SOCK_STREAM;
			UNICODE_STRING NodeName = RTL_CONSTANT_STRING(L"p.pstatp.com");
			UNICODE_STRING Port = RTL_CONSTANT_STRING(L"80");
			PADDRINFOEXW Result = { 0 };
			ntStatus = KsGetAddrInfo(&NodeName, &Port, &Hints, &Result);
			if (NT_SUCCESS(ntStatus))
			{
				DebuggerPrint("%S\n", Result->ai_canonname);

				PKSOCKET Socket = NULL;
				ntStatus = KsCreateConnectionSocket(&Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if (NT_SUCCESS(ntStatus))
				{
					ntStatus = KsConnect(Socket, Result->ai_addr);
					if (NT_SUCCESS(ntStatus))
					{
						ULONG Length = 0;
						ntStatus = KsSend(Socket, SendBuffer, sizeof(SendBuffer), 0, &Length);
						DebuggerPrint("[KS] Send:%u\n", Length);
						if (NT_SUCCESS(ntStatus))
						{
							BOOLEAN FoundHeader = FALSE;
							do
							{
								Length = 0;
								ntStatus = KsRecv(Socket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);

								RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])] = 0;
								RecvBuffer[Length] = 0;
								//DebuggerPrint("[KS] Recv:%u\n", Length);

								PCHAR Ret = NULL;
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

								/*DebuggerPrint("%s", Ret);*/
								//DebuggerPrint("%d : %s\n", Length - (ULONG)(Ret - RecvBuffer), NT_SUCCESS(ntStatus) ? "Suc" : "Fail");

								if (FoundHeader)
									/*ntStatus =*/ ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, Ret, Length - (ULONG)(Ret - RecvBuffer), NULL, NULL);

								//DebuggerPrint("%s", RecvBuffer);
								//DebuggerPrint("%d\n", (INT)RecvBuffer[(sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) / sizeof(RecvBuffer[0])]);
							} while (/*(Length == sizeof(RecvBuffer) - sizeof(RecvBuffer[0])) &&*/Length && NT_SUCCESS(ntStatus));

							//DbgBreakPoint();
						}
					}

					KsCloseSocket(Socket);
				}

				KsFreeAddrInfo(Result);
			}

			ZwClose(hFile);
		}
	}

	//DbgBreakPoint();

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

	/*{
	  int result;

	  char send_buffer[] = "Hello from WSK!";
	  char recv_buffer[1024] = { 0 };

	  int server_sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);

	  struct sockaddr_in addr;
	  addr.sin_family = AF_INET;
	  addr.sin_addr.s_addr = INADDR_ANY;
	  addr.sin_port = htons(9095);

	  result = bind(server_sockfd, (struct sockaddr*)&addr, sizeof(addr));
	  result = listen(server_sockfd, 1);

	  socklen_t addrlen = sizeof(addr);
	  int client_sockfd = accept(server_sockfd, (struct sockaddr*)&addr, &addrlen);

	  result = recv(client_sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0);
	  recv_buffer[sizeof(recv_buffer) - 1] = '\0';

	  DebuggerPrint("TCP server:\n%s\n", recv_buffer);

	  result = send(client_sockfd, send_buffer, sizeof(send_buffer), 0);

	  closesocket(client_sockfd);
	  closesocket(server_sockfd);
	}*/

	//
	// Destroy KSOCKET.
	//

	KsDestroy();

	//
	// Unload the driver immediately.
	//

	return STATUS_UNSUCCESSFUL;
}