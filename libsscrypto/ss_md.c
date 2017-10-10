#include <mbedtls/md.h>

void ss_hmac_ex(int md_type, const unsigned char *key, size_t keylen,
	const unsigned char *input, int ioff, size_t ilen,
	unsigned char output[20])
{
	mbedtls_md_hmac(mbedtls_md_info_from_type(md_type), key, keylen, input + ioff, ilen, output);
}

void ss_md(int md_type, const unsigned char *input, int ioff, size_t ilen,
	unsigned char output[20])
{
	mbedtls_md(mbedtls_md_info_from_type(md_type), input + ioff, ilen, output);
}
