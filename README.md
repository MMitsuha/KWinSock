# KWinSock

Give your kernel driver the access to network!

---

## Usage

Firstly you have to initialize `KWinSock` with `KsInitialize`

```
ntStatus = KsInitialize();
```

> https://github.com/caizhe666/KWinSock/blob/master/KWinSock/Main.c#L554

Then you have to initialize `ADDRINFOEXW` and `PADDRINFOEXW`

```
ADDRINFOEXW Hints = { 0 };
Hints.ai_flags |= AI_CANONNAME;
Hints.ai_family = AF_UNSPEC;
Hints.ai_socktype = SOCK_STREAM;                              // TCP mode
UNICODE_STRING NodeName = RTL_CONSTANT_STRING(LHOST_ROOT);    // Host name, eg: 192.168.1.1
UNICODE_STRING Port = RTL_CONSTANT_STRING(L"80");             // Port
PADDRINFOEXW Result = { 0 };
ntStatus = KsGetAddrInfo(&NodeName, &Port, &Hints, &Result);
```

> https://github.com/caizhe666/KWinSock/blob/master/KWinSock/Main.c#L602

Then you can create the sock with `KsCreateConnectionSocket`

```
ntStatus = KsCreateConnectionSocket(&Socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
```

> https://github.com/caizhe666/KWinSock/blob/master/KWinSock/Main.c#L615

Then you should connect to host with `KsConnect`

```
ntStatus = KsConnect(Socket, Result->ai_addr);
```
```

> https://github.com/caizhe666/KWinSock/blob/master/KWinSock/Main.c#L651

Finally you can send and receive message through `KsSend` and `KsRecv`

```
ntStatus = KsSend(Socket, SendBuffer, sizeof(SendBuffer), 0, &Length);
```

```
ntStatus = KsRecv(Socket, RecvBuffer, sizeof(RecvBuffer) - sizeof(RecvBuffer[0]), 0, &Length);
```

ENJOY YOURSELF

## LICENCE

> This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
> 
> This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
> 
> You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

## CONTACT

Telegram Group: https://t.me/miyamimitsuha

## Donate

Donate this project through Telegram, thank you!
