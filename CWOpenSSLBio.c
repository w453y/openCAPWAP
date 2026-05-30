/*
 * CWOpenSSLBio.c - OpenSSL 1.1.x compatible stub
 *
 * Original code used OpenSSL 1.0.x BIO_METHOD struct directly.
 * OpenSSL 1.1.x made BIO_METHOD and BIO opaque - struct is no longer public.
 * Since CW_NO_DTLS is defined, these functions are never called at runtime.
 * Full OpenSSL 1.1.x BIO rewrite to be done in Phase 2 (DTLS re-enable).
 */

#include "CWCommon.h"
#include "CWSecurity.h"

/*
 * BIO_s_memory - returns NULL stub (not used without DTLS)
 */
BIO_METHOD* BIO_s_memory(void) {
    return NULL;
}

/*
 * BIO_new_memory - stub matching CWSecurity.h signature
 * Real implementation requires OpenSSL 1.1.x BIO_meth_new() API
 * Not called when CW_NO_DTLS is defined
 */
BIO* BIO_new_memory(CWSocket sock, CWNetworkLev4Address* pSendAddress, CWSafeList* pRecvAddress) {
    (void)sock;
    (void)pSendAddress;
    (void)pRecvAddress;
    return NULL;
}
