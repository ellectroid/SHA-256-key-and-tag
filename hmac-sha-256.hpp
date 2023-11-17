#ifndef LIB_ELLIB_CRYPROGRAPHY_HMAC_SHA_256_HPP_
#define LIB_ELLIB_CRYPROGRAPHY_HMAC_SHA_256_HPP_

#include <cstdint>
#include "sha-256.hpp"

namespace ellib{
	class HMAC_SHA256{
	public:
		static bool digest(uint32_t* output_hmac, uint8_t* data, uint32_t data_bytelen,
				uint8_t* hmac_key, uint32_t hmac_key_bytelen,
				uint8_t* scratchbuffer_data_bytelen_plus64);
		static bool verify(uint32_t* cmp_hmac, uint8_t* data, uint32_t data_bytelen,
				uint8_t* hmac_key, uint32_t hmac_key_bytelen,
				uint8_t* scratchbuffer_data_bytelen_plus64);

	};
}




#endif /* LIB_ELLIB_CRYPROGRAPHY_HMAC_SHA_256_HPP_ */
