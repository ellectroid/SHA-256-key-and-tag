#include "hmac-sha-256.hpp"

namespace ellib{

bool HMAC_SHA256::digest(uint32_t* output_hmac, uint8_t* data, uint32_t data_bytelen,
				uint8_t* hmac_key, uint32_t hmac_key_bytelen,
				uint8_t* scratchbuffer_data_bytelen_plus64){
			/* See https://www.ietf.org/rfc/rfc2104.txt for how HMAC works */

			alignas(4) uint8_t temp_8[64 + 32] = { 0 };
			uint32_t* temp_32 = reinterpret_cast<uint32_t*>(temp_8);
			alignas(4) uint8_t ipad[64];
			alignas(4) uint8_t opad[64];
			for (uint8_t i = 0; i < 64; i++) {
				ipad[i] = 0x36;
				opad[i] = 0x5C;
			}
			/* Check key length. If the key is longer than SHA-256 block size (512 bits/64 bytes), take key hash and use that as a key */
			/* we can use step1output as a temporary storage for key */
			if (hmac_key_bytelen > 64) {
				SHA256::digest(temp_32, hmac_key, hmac_key_bytelen);
				hmac_key_bytelen = 32;
			}
			else {
				for (uint8_t i = 0; i < hmac_key_bytelen; i++) {
					temp_8[i] = hmac_key[i];
				}
			}

			for (uint8_t i = 0; i < hmac_key_bytelen; i++) {
				ipad[i] ^= temp_8[i];
				opad[i] ^= temp_8[i];
			}

			/* We have ipad and opad ready. Now we concatenate ipad to data and take hash of that */
			for (uint32_t i = 0; i < 64; i++) {
				scratchbuffer_data_bytelen_plus64[i] = ipad[i];
			}
			for (uint32_t i = 0; i < (data_bytelen); i++) {
				scratchbuffer_data_bytelen_plus64[i + 64] = data[i];
			}

			/* Since we don't need formatted key in temp[] anymore, we can reuse temp for store HMAC step 1 hash result */
			SHA256::digest(&(temp_32[16]),scratchbuffer_data_bytelen_plus64, 64 + data_bytelen);
			for (uint32_t i = 0; i < 64; i++) {
				temp_8[i] = opad[i];
			}

			/* Placed opad, placed hash of step1, the only thing left is to calculate hash of step1output */
			SHA256::digest(output_hmac, temp_8, 96);
	return true;
}

bool HMAC_SHA256::verify(uint32_t* cmp_hmac, uint8_t* data, uint32_t data_bytelen,
		uint8_t* hmac_key, uint32_t hmac_key_bytelen,
		uint8_t* scratchbuffer_data_bytelen_plus64){
	uint32_t calculated_hmac[8];
	digest(calculated_hmac, data, data_bytelen,
			hmac_key, hmac_key_bytelen,
			scratchbuffer_data_bytelen_plus64);
	int8_t errcnt = 0;
		for (uint8_t i = 0; i < 8; i++) {
			/* FOR CONSTANT TIME EXECUTION */
			if (cmp_hmac[i] != calculated_hmac[i]) {
				errcnt++;
			}
			/* FOR SPEED
			if (cmp_hmac[i] != calculated_hmac[i]) {
				return false;
			}
			*/
		}
		if (errcnt == 0)
			return true;
		return false;
}


}
