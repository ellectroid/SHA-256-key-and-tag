#include "sha-256.hpp"

namespace ellib {

static const uint32_t sha256_round_constants[64] = { 0x428A2F98, 0x71374491,
		0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
		0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D,
		0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB,
		0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08,
		0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB,
		0xBEF9A3F7, 0xC67178F2 };

bool SHA256::digest(uint32_t *output, uint8_t *data, size_t data_bytelen) {

	output[0] = 0x6A09E667;
	output[1] = 0xBB67AE85;
	output[2] = 0x3C6EF372;
	output[3] = 0xA54FF53A;
	output[4] = 0x510E527F;
	output[5] = 0x9B05688C;
	output[6] = 0x1F83D9AB;
	output[7] = 0x5BE0CD19;

	/* ========== Preprocessing and padding ========== */
	uint32_t padding_byte_length = 64 - data_bytelen % 64;
	if (padding_byte_length < 9) {
		/* if appended 1 and bitlength don't fit into current chunk, extend padding to another chunk */
		padding_byte_length += 64;

	}

	uint8_t padding[padding_byte_length] = { 0 };
	padding[0] = 0x80; //Append "1"

	/* Writing size in big endian format into the last two 32-bit words of padding */
	uint32_t input_bit_length = (data_bytelen) * 8;
	uint8_t *input_bit_length_bytes =
			reinterpret_cast<uint8_t*>(&input_bit_length);
	/* Reverse bytes for little endian system */
	input_bit_length_bytes[0] ^= input_bit_length_bytes[3];
	input_bit_length_bytes[3] ^= input_bit_length_bytes[0];
	input_bit_length_bytes[0] ^= input_bit_length_bytes[3];
	input_bit_length_bytes[1] ^= input_bit_length_bytes[2];
	input_bit_length_bytes[2] ^= input_bit_length_bytes[1];
	input_bit_length_bytes[1] ^= input_bit_length_bytes[2];
	for (uint8_t i = 0; i < 4; i++) {
		padding[padding_byte_length - 4 + i] = input_bit_length_bytes[i]; //Accessing only by byte
	}

	/* ========== Main loop ========== */
	uint32_t data_index = 0;
	for (uint32_t chunk = 0; chunk < (padding_byte_length + data_bytelen) / 64;
			chunk++) {

		alignas(4) uint8_t message_schedule[64 * 4];
		uint32_t *message_schedule_32 =
				reinterpret_cast<uint32_t*>(message_schedule);

		for (uint8_t i = 0; i < 64; i++) {
			if (data_index < data_bytelen) {
				message_schedule[i] =data[data_index];
				data_index++;
			} else {
				message_schedule[i] = padding[data_index - data_bytelen];
				data_index++;
			}
		}

		/* Reverse data bytes upon fetching */
		for (uint8_t i = 0; i < 16; i++) {
			message_schedule[4 * i + 0] ^= message_schedule[4 * i + 3];
			message_schedule[4 * i + 3] ^= message_schedule[4 * i + 0];
			message_schedule[4 * i + 0] ^= message_schedule[4 * i + 3];
			message_schedule[4 * i + 1] ^= message_schedule[4 * i + 2];
			message_schedule[4 * i + 2] ^= message_schedule[4 * i + 1];
			message_schedule[4 * i + 1] ^= message_schedule[4 * i + 2];
		}

		for (uint8_t i = 16; i < 64; i++) {
			uint32_t S0 = ((message_schedule_32[i - 15] >> 7)
					| (message_schedule_32[i - 15] << (32 - 7)))
					^ ((message_schedule_32[i - 15] >> 18)
							| (message_schedule_32[i - 15] << (32 - 18)))
					^ (message_schedule_32[i - 15] >> 3);
			uint32_t S1 = ((message_schedule_32[i - 2] >> 17)
					| (message_schedule_32[i - 2] << (32 - 17)))
					^ ((message_schedule_32[i - 2] >> 19)
							| (message_schedule_32[i - 2] << (32 - 19)))
					^ (message_schedule_32[i - 2] >> 10);
			message_schedule_32[i] = message_schedule_32[i - 16]
					+ message_schedule_32[i - 7] + S0 + S1;
		}

		uint32_t working_vars[8];
		for (uint8_t i = 0; i < 8; i++) {
			working_vars[i] = (output)[i];
		}

		for (uint8_t i = 0; i < 64; i++) {
			uint32_t S1 =
					((working_vars[4] >> 6) | (working_vars[4] << (32 - 6)))
							^ ((working_vars[4] >> 11)
									| (working_vars[4] << (32 - 11)))
							^ ((working_vars[4] >> 25)
									| (working_vars[4] << (32 - 25)));
			uint32_t ch = (working_vars[4] & working_vars[5])
					^ ((~working_vars[4]) & working_vars[6]);
			uint32_t temp1 = working_vars[7] + S1 + ch
					+ sha256_round_constants[i] + message_schedule_32[i];
			uint32_t S0 =
					((working_vars[0] >> 2) | (working_vars[0] << (32 - 2)))
							^ ((working_vars[0] >> 13)
									| (working_vars[0] << (32 - 13)))
							^ ((working_vars[0] >> 22)
									| (working_vars[0] << (32 - 22)));
			uint32_t maj = (working_vars[0] & working_vars[1])
					^ (working_vars[0] & working_vars[2])
					^ (working_vars[1] & working_vars[2]);
			uint32_t temp2 = S0 + maj;

			working_vars[7] = working_vars[6];
			working_vars[6] = working_vars[5];
			working_vars[5] = working_vars[4];
			working_vars[4] = working_vars[3] + temp1;
			working_vars[3] = working_vars[2];
			working_vars[2] = working_vars[1];
			working_vars[1] = working_vars[0];
			working_vars[0] = temp1 + temp2;

		}

		for (uint8_t i = 0; i < 8; i++) {
			(output)[i] += working_vars[i];
		}

	}

	uint8_t* output_8 = (uint8_t*) output;
	for(uint8_t i = 0; i < 8; i++){
		output_8[4*i + 0] ^= output_8[4*i + 3];
		output_8[4*i + 3] ^= output_8[4*i + 0];
		output_8[4*i + 0] ^= output_8[4*i + 3];
		output_8[4*i + 1] ^= output_8[4*i + 2];
		output_8[4*i + 2] ^= output_8[4*i + 1];
		output_8[4*i + 1] ^= output_8[4*i + 2];

	}

	return true;
}
bool SHA256::verify(uint32_t *cmphash, uint8_t *data, size_t data_bytelen) {
	uint32_t recalculated_hash[8];
	SHA256::digest(recalculated_hash, data, data_bytelen);
	int8_t errcnt = 0;
	for (uint8_t i = 0; i < 8; i++) {
		/* FOR CONSTANT TIME EXECUTION */
		if (cmphash[i] != recalculated_hash[i]) {
			errcnt++;
		}
		/* FOR SPEED
		if (cmphash[i] != recalculated_hash[i]) {
			return false;
		}
		*/
	}
	return !errcnt;
}
}

