#ifndef LIB_ELLIB_CRYPROGRAPHY_PBKDF2_SHA256_HPP_
#define LIB_ELLIB_CRYPROGRAPHY_PBKDF2_SHA256_HPP_

#include <cstdint>
#include "hmac-sha-256.hpp"
namespace ellib{
	class PBKDF2_SHA256{
	public:
		static bool generate_subkey(uint8_t* output_derived_key, uint32_t output_bytelen, uint8_t* input_key, uint32_t input_key_bytelen, uint8_t* salt, uint32_t saltbytelen, uint32_t iterations, uint8_t* scratchram_saltlen_plus_200);
	};
}




#endif /* LIB_ELLIB_CRYPROGRAPHY_PBKDF2_SHA256_HPP_ */
