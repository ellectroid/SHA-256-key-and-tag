#ifndef LIB_ELLIB_CRYPROGRAPHY_SHA_256_HPP_
#define LIB_ELLIB_CRYPROGRAPHY_SHA_256_HPP_

#include <cstdint>

namespace ellib{
	class SHA256{
	public:
		static bool digest(uint32_t* output, uint8_t* data, size_t databytelen);
		static bool verify(uint32_t* cmphash, uint8_t* data, size_t databytelen);
	};
}




#endif /* LIB_ELLIB_CRYPROGRAPHY_SHA_256_HPP_ */
