#include "CWCommon.h"

#ifndef IP_MTU
#define IP_MTU 14
#endif

typedef struct {
    CWSocket sock;
    CWNetworkLev4Address sendAddress;
    CWSafeList* pRecvAddress;
    unsigned int nMtu;
} BIO_memory_data;

static int memory_write(BIO *h, const char *buf, int num);
static int memory_read(BIO *h, char *buf, int size);
static int memory_puts(BIO *h, const char *str);
static long memory_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int memory_new(BIO *h);
static int memory_free(BIO *data);

static BIO_METHOD *methods_memory = NULL;

BIO_METHOD* BIO_s_memory(void)
{
    if (methods_memory == NULL) {
        methods_memory = BIO_meth_new(BIO_TYPE_DGRAM, "memory packet");
        if (methods_memory == NULL) return NULL;
        BIO_meth_set_write(methods_memory, memory_write);
        BIO_meth_set_read(methods_memory, memory_read);
        BIO_meth_set_puts(methods_memory, memory_puts);
        BIO_meth_set_ctrl(methods_memory, memory_ctrl);
        BIO_meth_set_create(methods_memory, memory_new);
        BIO_meth_set_destroy(methods_memory, memory_free);
    }
    return methods_memory;
}

BIO* BIO_new_memory(CWSocket sock, CWNetworkLev4Address* pSendAddress, CWSafeList* pRecvAddress)
{
    BIO *ret;
    BIO_memory_data* pData;

    ret = BIO_new(BIO_s_memory());
    if (ret == NULL) return NULL;

    pData = (BIO_memory_data*)BIO_get_data(ret);
    pData->sock = sock;
    memcpy(&pData->sendAddress, pSendAddress, sizeof(CWNetworkLev4Address));
    pData->pRecvAddress = pRecvAddress;

    return ret;
}

static int memory_new(BIO *bi)
{
    BIO_memory_data *pData = malloc(sizeof(BIO_memory_data));
    if (!pData) return 0;
    memset(pData, 0, sizeof(BIO_memory_data));
    BIO_set_data(bi, pData);
    BIO_set_init(bi, 1);
    return 1;
}

static int memory_free(BIO *a)
{
    if (a == NULL) return 0;
    free(BIO_get_data(a));
    BIO_set_data(a, NULL);
    return 1;
}

static int memory_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    char* buf;
    int size;
    BIO_memory_data* pData = (BIO_memory_data*)BIO_get_data(b);

    CWLockSafeList(pData->pRecvAddress);
    while (CWGetCountElementFromSafeList(pData->pRecvAddress) == 0)
        CWWaitElementFromSafeList(pData->pRecvAddress);

    buf = (char*)CWRemoveHeadElementFromSafeList(pData->pRecvAddress, &size);
    CWUnlockSafeList(pData->pRecvAddress);

    if ((buf == NULL) || (size <= 0))
        CWLog("Warning empty buffer");
    else {
        ret = ((size < outl) ? size : outl) - 4;
        memcpy(out, buf + 4, ret);
        CW_FREE_OBJECT(buf);
    }
    return ret;
}

static int memory_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    char strBuffer[MAX_UDP_PACKET_SIZE];
    BIO_memory_data* pData = (BIO_memory_data*)BIO_get_data(b);

    strBuffer[0] = (char)(CW_PROTOCOL_VERSION << 4) | (char)(CW_PACKET_CRYPT);
    strBuffer[1] = strBuffer[2] = strBuffer[3] = 0;
    memcpy(&strBuffer[4], in, inl);

    errno = 0;
	{
		struct sockaddr_in *_a = (struct sockaddr_in*)&pData->sendAddress;
	}
    /* Try send() first (connected socket/WTP), fall back to sendto() (server/AC) */
	{
		struct sockaddr_in *_a=(struct sockaddr_in*)&pData->sendAddress;
	}
    ret = sendto(pData->sock, strBuffer, inl + 4, 0,
                 (struct sockaddr*)&pData->sendAddress,
                 sizeof(struct sockaddr_storage));
    if (ret < 0 && errno == EISCONN) {
        /* Connected socket - use send() without address */
        ret = send(pData->sock, strBuffer, inl + 4, 0);
    }
    if (ret <= 0) {
        if (errno == EINTR)
            BIO_set_retry_write(b);
    } else {
        ret -= 4;
    }
    return ret;
}

static long memory_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    long sockopt_val = 0;
    unsigned int sockopt_len = 0;
    BIO_memory_data* pData = (BIO_memory_data*)BIO_get_data(b);

    switch (cmd) {
        case BIO_CTRL_RESET:        ret = 0; break;
        case BIO_CTRL_EOF:          ret = 0; break;
        case BIO_CTRL_INFO:         ret = 0; break;
        case BIO_CTRL_GET_CLOSE:    ret = 0; break;
        case BIO_CTRL_SET_CLOSE:    break;
        case BIO_CTRL_WPENDING:     ret = 0; break;
        case BIO_CTRL_PENDING:      ret = 0; break;
        case BIO_CTRL_DUP:          ret = 1; break;
        case BIO_CTRL_FLUSH:        ret = 1; break;
        case BIO_CTRL_PUSH:         ret = 0; break;
        case BIO_CTRL_POP:          ret = 0; break;
        case BIO_CTRL_DGRAM_QUERY_MTU:
            sockopt_len = sizeof(sockopt_val);
            if ((ret = getsockopt(pData->sock, IPPROTO_IP, IP_MTU,
                                  (void*)&sockopt_val, &sockopt_len)) < 0
                || sockopt_val < 0) {
                ret = 0;
            } else {
                pData->nMtu = sockopt_val;
                ret = sockopt_val;
            }
            break;
        case BIO_CTRL_DGRAM_GET_MTU: ret = pData->nMtu; break;
        case BIO_CTRL_DGRAM_SET_MTU: pData->nMtu = num; ret = num; break;
        default: ret = 0; break;
    }
    return ret;
}

static int memory_puts(BIO *bp, const char *str)
{
    return memory_write(bp, str, strlen(str));
}
