/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mock_system_func.h"
#include "dhcp_client_state_machine.h"

using namespace OHOS::DHCP;

static bool g_mockTag = false;
static int NUM_TWO = 2;
static int NUM_THREE = 3;
static int NUM_FOUR = 4;

MockSystemFunc &MockSystemFunc::GetInstance()
{
    static MockSystemFunc gMockSystemFunc;
    return gMockSystemFunc;
};

MockSystemFunc::MockSystemFunc()
{}

void MockSystemFunc::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool MockSystemFunc::GetMockFlag(void)
{
    return g_mockTag;
}

extern "C" {
int __real_open(const char *__file, int __oflag);
int __wrap_open(const char *__file, int __oflag)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().open(__file, __oflag);
    } else {
        return __real_open(__file, __oflag);
    }
}

int __real_close(int fd);
int __wrap_close(int fd)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().close(fd);
    } else {
        return __real_close(fd);
    }
}

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().write(fd, buf, count);
    } else {
        return __real_write(fd, buf, count);
    }
}

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().read(fd, buf, count);
    } else {
        return __real_read(fd, buf, count);
    }
}

int __real_socket(int __domain, int __type, int __protocol);
int __wrap_socket(int __domain, int __type, int __protocol)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().socket(__domain, __type, __protocol);
    } else {
        return __real_socket(__domain, __type, __protocol);
    }
}

int __real_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen);
int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().setsockopt(__fd, __level, __optname, __optval, __optlen);
    } else {
        return __real_setsockopt(__fd, __level, __optname, __optval, __optlen);
    }
}

int __real_ioctl(int __fd, unsigned long __request, struct sockaddr *__ifreq);
int __wrap_ioctl(int __fd, unsigned long __request, struct sockaddr *__ifreq)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().ioctl(__fd, __request, __ifreq);
    } else {
        return __real_ioctl(__fd, __request, __ifreq);
    }
}

int __real_bind(int __fd, const struct sockaddr *__addr, socklen_t __len);
int __wrap_bind(int __fd, const struct sockaddr *__addr, socklen_t __len)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().bind(__fd, __addr, __len);
    } else {
        return __real_bind(__fd, __addr, __len);
    }
}

int __real_listen(int __fd, int __n);
int __wrap_listen(int __fd, int __n)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().listen(__fd, __n);
    } else {
        return __real_listen(__fd, __n);
    }
}

int __real_connect(int __fd, const struct sockaddr *__addr, socklen_t __len);
int __wrap_connect(int __fd, const struct sockaddr *__addr, socklen_t __len)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().connect(__fd, __addr, __len);
    } else {
        return __real_connect(__fd, __addr, __len);
    }
}

int __real_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int __wrap_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    std::unique_ptr<OHOS::DHCP::DhcpClientStateMachine> testMachine;
    if (g_mockTag) {
        int nRet = MockSystemFunc::GetInstance().select(nfds, readfds, writefds, exceptfds, timeout);
        FD_ZERO(readfds);
        if (nRet == 1) {
            FD_SET(testMachine->GetPacketReadSockFd(), readfds);
        } else if (nRet == NUM_TWO) {
            FD_SET(testMachine->GetSigReadSockFd(), readfds);
        } else if (nRet == NUM_FOUR) {
            FD_SET(testMachine->GetSigReadSockFd(), readfds);
        }
        return nRet;
    } else {
        return __real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
}

ssize_t __real_sendto(int fd, const void *buf, size_t count, int flags, const struct sockaddr *addr, socklen_t len);
ssize_t __wrap_sendto(int fd, const void *buf, size_t count, int flags, const struct sockaddr *addr, socklen_t len)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().sendto(fd, buf, count, flags, addr, len);
    } else {
        return __real_sendto(fd, buf, count, flags, addr, len);
    }
}

int __real_socketpair(int address, int type, int protocol, int *socket);
int __wrap_socketpair(int address, int type, int protocol, int *socket)
{
    if (g_mockTag) {
        return MockSystemFunc::GetInstance().socketpair(address, type, protocol, socket);
    } else {
        return __real_socketpair(address, type, protocol, socket);
    }
}
}
