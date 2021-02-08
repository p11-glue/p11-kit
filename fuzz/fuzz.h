#ifndef __P11_FUZZ_H__
#define __P11_FUZZ_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __P11_FUZZ_H__ */
