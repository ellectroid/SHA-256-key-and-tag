#include "pbkdf2-sha-256.hpp"

namespace ellib{
bool PBKDF2_SHA256::generate_subkey(uint8_t* output_derived_key, uint32_t output_bytelen, uint8_t* input_key, uint32_t input_key_bytelen, uint8_t* salt, uint32_t salt_bytelen, uint32_t iterations, uint8_t* scratchram){
	/* https://datatracker.ietf.org/doc/html/rfc2898 */

	/* Initialize scratch RAM stack pointer */
	uint32_t scratchram_str_ascending_stack_ptr = 0;

	uint32_t full_output_blocks = output_bytelen / 32;
	uint32_t partial_output_block_bytelen = output_bytelen % 32;

	/* Reserve scratch RAM spot for salt appended by big endian block number */
	/* make sure it's 4-byte aligned */
	if(((intptr_t)scratchram & 0x03) != 0){
		scratchram_str_ascending_stack_ptr = 4 - ((intptr_t)scratchram & 0x03);
	}
	uint8_t *U0 = &scratchram[scratchram_str_ascending_stack_ptr];
	scratchram_str_ascending_stack_ptr = scratchram_str_ascending_stack_ptr
			+ salt_bytelen + 4;
	for (uint32_t i = 0; i < salt_bytelen; i++) {
		U0[i] = salt[i];
	}

	/* Reserve scratch RAM for Uprev, Ucurrent */
	uint8_t *Uprev = &scratchram[scratchram_str_ascending_stack_ptr];
	scratchram_str_ascending_stack_ptr += 32;
	uint8_t *Ucurr = &scratchram[scratchram_str_ascending_stack_ptr];
	scratchram_str_ascending_stack_ptr += 32;
	uint8_t *Utemp; //temp pointer to swap the two around

	uint8_t *DerivedKeyLastBlock =
			&scratchram[scratchram_str_ascending_stack_ptr];
	scratchram_str_ascending_stack_ptr += 32;

	for (uint32_t CurrentBlock = 1; CurrentBlock <= full_output_blocks;
			CurrentBlock++) {
		U0[salt_bytelen + 0] = static_cast<uint8_t>(CurrentBlock >> 24);
		U0[salt_bytelen + 1] = static_cast<uint8_t>(CurrentBlock >> 16);
		U0[salt_bytelen + 2] = static_cast<uint8_t>(CurrentBlock >> 8);
		U0[salt_bytelen + 3] = static_cast<uint8_t>(CurrentBlock >> 0);
		/* Calculate U1 */
		HMAC_SHA256::digest(reinterpret_cast<uint32_t*>(Ucurr), U0, salt_bytelen + 4, input_key,
				input_key_bytelen,
				&scratchram[scratchram_str_ascending_stack_ptr]);
		Utemp = Ucurr;
		Ucurr = Uprev;
		Uprev = Utemp;
		for (uint32_t i = 0; (i < 32); i++) {
			output_derived_key[(CurrentBlock - 1) * 32 + i] = Uprev[i];
		}
		for (uint32_t c = 2; c <= iterations; c++) {
			HMAC_SHA256::digest(reinterpret_cast<uint32_t*>(Ucurr), Uprev, 32, input_key,
					input_key_bytelen,
					&scratchram[scratchram_str_ascending_stack_ptr]);
			Utemp = Ucurr;
			Ucurr = Uprev;
			Uprev = Utemp;
			for (uint32_t i = 0; (i < 32); i++) {
				output_derived_key[(CurrentBlock - 1) * 32 + i] ^= Uprev[i];
			}
		}
	}

	if (partial_output_block_bytelen != 0) {

		/* For the partial block, do all the same, but output to temp buffer */
		U0[salt_bytelen + 0] = static_cast<uint8_t>((full_output_blocks + 1)
				>> 24);
		U0[salt_bytelen + 1] = static_cast<uint8_t>((full_output_blocks + 1)
				>> 16);
		U0[salt_bytelen + 2] = static_cast<uint8_t>((full_output_blocks + 1)
				>> 8);
		U0[salt_bytelen + 3] = static_cast<uint8_t>((full_output_blocks + 1)
				>> 0);
		/* Calculate U1 */
		HMAC_SHA256::digest(reinterpret_cast<uint32_t*>(Ucurr), U0, salt_bytelen + 4, input_key,
				input_key_bytelen,
				&scratchram[scratchram_str_ascending_stack_ptr]);
		Utemp = Ucurr;
		Ucurr = Uprev;
		Uprev = Utemp;
		for (uint32_t i = 0; (i < 32); i++) {
			DerivedKeyLastBlock[i] = Uprev[i];
		}
		for (uint32_t c = 2; c <= iterations; c++) {
			HMAC_SHA256::digest(reinterpret_cast<uint32_t*>(Ucurr), Uprev, 32, input_key,
					input_key_bytelen,
					&scratchram[scratchram_str_ascending_stack_ptr]);
			Utemp = Ucurr;
			Ucurr = Uprev;
			Uprev = Utemp;
			for (uint32_t i = 0; (i < 32); i++) {
				DerivedKeyLastBlock[i] ^= Uprev[i];
			}
		}

		for (uint8_t i = 0; i < partial_output_block_bytelen; i++) {
			output_derived_key[32 * full_output_blocks + i] = DerivedKeyLastBlock[i];
		}

	}

	return true;
}

}
