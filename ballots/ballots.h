#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct ByteBuffer {
  uint8_t *ptr;
  uintptr_t length;
  uintptr_t capacity;
};

extern "C" {

/// Generates vector of ciphertexts
ByteBuffer generate_acc(const uint8_t *buffer, uintptr_t length);

/// Verifies vote validity
ByteBuffer verify_vote(const uint8_t *buffer, uintptr_t length);

/// Add vote to result vector
ByteBuffer add_votes(const uint8_t *buffer, uintptr_t length);

void empty_buffer(ByteBuffer buffer);

}  // extern "C"
