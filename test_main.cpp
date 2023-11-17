/* for fancy printing only */
#include <iostream>
#include <iomanip>

#include "sha-256.hpp"
#include "hmac-sha-256.hpp"
#include "pbkdf2-sha-256.hpp"

int main() {
	std::cout << "*** SHA-256 library test ***" << std::endl;

	/* Testing against:
	 * SHA-256: 			https://emn178.github.io/online-tools/sha256.html
	 * HMAC-SHA-256:		https://emn178.github.io/online-tools/sha256.html
	 * PBKDF2-HMAC-SHA-256: https://www.dcode.fr/pbkdf2-hash
	 * 						https://neurotechnics.com/tools/pbkdf2-test
	 *  */

	/* Test data */
	char message[] = "Hello, world!";
	uint32_t message_size = sizeof(message) - 1; //-1 to exclude null term.
	std::cout << "Test message: " << std::endl;
	std::cout << message << std::endl;
	std::cout << std::endl;

	/* ================================ */
	/* SHA-256 test */
	std::cout << "SHA-256: " << std::endl;
	uint32_t message_hash[8] = { 0 };
	ellib::SHA256::digest(message_hash, (uint8_t*) message, message_size);
	for (unsigned int i = 0; i < sizeof(message_hash); i++) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex
				<< int(((uint8_t*) message_hash)[i]);
	}
	std::cout << std::endl;
	std::cout << std::endl;

	/* ================================ */
	std::cout << "HMAC-SHA-256" << std::endl;
	uint8_t message_hmac_key[32] = { 0 };
	message_hmac_key[0] = 0x30;
	message_hmac_key[1] = '1';
	message_hmac_key[2] = '2';
	message_hmac_key[3] = 0x33;
	uint32_t hmac_key_length = 4;
	uint32_t message_hmac_tag[8] = { 0 };
	uint8_t hmac_scratchmem[sizeof(message) + 64];

	ellib::HMAC_SHA256::digest(message_hmac_tag, (uint8_t*) message,
			message_size, message_hmac_key, hmac_key_length, hmac_scratchmem);
	std::cout << "key:" << std::endl;
	for (unsigned int i = 0; i < hmac_key_length; i++) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex
				<< int(((uint8_t*) message_hmac_key)[i]);
	}
	std::cout << std::endl;
	std::cout << "tag:" << std::endl;
	for (unsigned int i = 0; i < sizeof(message_hmac_tag); i++) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex
				<< int(((uint8_t*) message_hmac_tag)[i]);
	}
	std::cout << std::endl;
	std::cout << std::endl;

	/* ================================ */
	std::cout << "PBKDF2-HMAC-SHA-256" << std::endl;
	//memory required: 200 + salt length
	uint8_t pbkdf2_salt[32] = { 0 };
	pbkdf2_salt[0] = 0x35;
	pbkdf2_salt[1] = '6';
	pbkdf2_salt[2] = '7';
	pbkdf2_salt[3] = 0x38;
	pbkdf2_salt[4] = 0x39;
	uint32_t pbkdf2_salt_len = 4;
	uint32_t pbkdf2_iterations = 8;
	uint8_t derived_key[80] = { 0 };
	uint32_t derived_key_len = 33;
	uint8_t pbkdf2_scratchmem[200 + sizeof(pbkdf2_salt)];
	for(uint32_t i = 0; i < sizeof(pbkdf2_scratchmem); i++){
		pbkdf2_scratchmem[i] = 0xA5;
	}

	uint8_t* master_key = (uint8_t*) message;
	uint32_t master_key_len = message_size;
	ellib::PBKDF2_SHA256::generate_subkey(derived_key, derived_key_len,
			master_key, master_key_len, pbkdf2_salt,
			pbkdf2_salt_len, pbkdf2_iterations, pbkdf2_scratchmem);

	std::cout << "salt:" << std::endl;
	for (unsigned int i = 0; i < pbkdf2_salt_len; i++) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex
				<< int(((uint8_t*) pbkdf2_salt)[i]);
	}
	std::cout << std::endl;

	std::cout << "derived key:" << std::endl;
	for (unsigned int i = 0; i < derived_key_len; i++) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex
				<< int(((uint8_t*) derived_key)[i]);
	}
	std::cout << std::endl;

	return 0;
}
