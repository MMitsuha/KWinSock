#pragma once
#include <ntddk.h>
#include <wsk.h>

typedef struct _KSOCKET KSOCKET, * PKSOCKET;

NTSTATUS
NTAPI
KsInitialize(
	VOID
);

VOID
NTAPI
KsDestroy(
	VOID
);

NTSTATUS
NTAPI
KsGetAddrInfo(
	_In_ PUNICODE_STRING NodeName,
	_In_ PUNICODE_STRING ServiceName,
	_In_ PADDRINFOEXW Hints,
	_Out_ PADDRINFOEXW* Result
);

VOID
NTAPI
KsFreeAddrInfo(
	_In_ PADDRINFOEXW AddrInfo
);

NTSTATUS
NTAPI
KsCreateSocket(
	_Out_ PKSOCKET* Socket,
	_In_ ADDRESS_FAMILY AddressFamily,
	_In_ USHORT SocketType,
	_In_ ULONG Protocol,
	_In_ ULONG Flags
);

NTSTATUS
NTAPI
KsCreateConnectionSocket(
	_Out_ PKSOCKET* Socket,
	_In_ ADDRESS_FAMILY AddressFamily,
	_In_ USHORT SocketType,
	_In_ ULONG Protocol
);

NTSTATUS
NTAPI
KsCreateListenSocket(
	_Out_ PKSOCKET* Socket,
	_In_ ADDRESS_FAMILY AddressFamily,
	_In_ USHORT SocketType,
	_In_ ULONG Protocol
);

NTSTATUS
NTAPI
KsCreateDatagramSocket(
	_Out_ PKSOCKET* Socket,
	_In_ ADDRESS_FAMILY AddressFamily,
	_In_ USHORT SocketType,
	_In_ ULONG Protocol
);

NTSTATUS
NTAPI
KsCloseSocket(
	_In_ PKSOCKET Socket
);

NTSTATUS
NTAPI
KsBind(
	_In_ PKSOCKET Socket,
	_In_ PSOCKADDR LocalAddress
);

NTSTATUS
NTAPI
KsAccept(
	_In_ PKSOCKET Socket,
	_Out_ PKSOCKET* NewSocket,
	_Out_opt_ PSOCKADDR LocalAddress,
	_Out_opt_ PSOCKADDR RemoteAddress
);

NTSTATUS
NTAPI
KsConnect(
	_In_ PKSOCKET Socket,
	_In_ PSOCKADDR RemoteAddress
);

NTSTATUS
NTAPI
KsSendRecvTcp(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ ULONG Flags,
	_Out_opt_ PULONG LengthReturned,
	_In_ BOOLEAN Send
);

NTSTATUS
NTAPI
KsSendRecvUdp(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_Inout_ PULONG Length,
	_In_ ULONG Flags,
	_In_ PSOCKADDR RemoteAddress,
	_In_ BOOLEAN Send
);

NTSTATUS
NTAPI
KsSend(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ ULONG Flags,
	_Out_opt_ PULONG LengthReturned
);

NTSTATUS
NTAPI
KsRecv(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ ULONG Flags,
	_Out_opt_ PULONG LengthReturned
);

NTSTATUS
NTAPI
KsSendTo(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_Inout_ PULONG Length,
	_In_ ULONG Flags,
	_In_ PSOCKADDR RemoteAddress
);

NTSTATUS
NTAPI
KsRecvFrom(
	_In_ PKSOCKET Socket,
	_In_ PVOID Buffer,
	_Inout_ PULONG Length,
	_In_ ULONG Flags,
	_In_ PSOCKADDR RemoteAddress
);

static
inline
UINT32
htonl(
	_In_ UINT32 hostlong
)
{
	return RtlUlongByteSwap(hostlong);
}

static
inline
UINT16
htons(
	_In_ UINT16 hostshort
)
{
	return RtlUshortByteSwap(hostshort);
}

static
inline
UINT32
ntohl(
	_In_ UINT32 netlong
)
{
	return RtlUlongByteSwap(netlong);
}

static
inline
UINT16
ntohs(
	_In_ UINT16 netshort
)
{
	return RtlUshortByteSwap(netshort);
}