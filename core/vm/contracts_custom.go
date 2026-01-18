package vm

/*
#cgo LDFLAGS: -L$/usr/lib -lballots -Wl,-rpath=$/usr/lib
#include <stdint.h>
#include <stdlib.h>
typedef struct {
  uint8_t *ptr;
  uintptr_t length;
  uintptr_t capacity;
} ByteBuffer;

extern ByteBuffer generate_acc(const uint8_t *buffer, uintptr_t length);
extern ByteBuffer verify_vote(const uint8_t *buffer, uintptr_t length);
extern ByteBuffer verify_signature(const uint8_t *buffer, uintptr_t length);
extern ByteBuffer add_votes(const uint8_t *buffer, uintptr_t length);
extern void empty_buffer(ByteBuffer buffer);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func DecodeByteBuffer(buffer C.ByteBuffer) ([]byte, error) {
	if buffer.ptr == nil || buffer.length == 0 {
		return nil, fmt.Errorf("Unexpected error")
	}

	result := C.GoBytes(unsafe.Pointer(buffer.ptr), C.int(buffer.length))
	C.empty_buffer(buffer)

	return result, nil
}

type generateAcc struct {}

func (c *generateAcc) Name() string {
	return "GENACC"
}

func (c *generateAcc) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *generateAcc) Run(input []byte) ([]byte, error) {
	var cInput *C.uint8_t
	if len(input) > 0 {
		cInput = (*C.uint8_t)(&input[0])
	}

	result := C.generate_acc(cInput, C.uintptr_t(len(input)))

	decoded, err := DecodeByteBuffer(result)

	return decoded, err
}

type encryptedSum struct {}

func (c *encryptedSum) Name() string {
	return "ENCSUM"
}

func (c *encryptedSum) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *encryptedSum) Run(input []byte) ([]byte, error) {
	var cInput *C.uint8_t
	if len(input) > 0 {
		cInput = (*C.uint8_t)(&input[0])
	}

	result := C.add_votes(cInput, C.uintptr_t(len(input)))
	
	return DecodeByteBuffer(result)
}

type verifyVoteZKP struct {}

func (c *verifyVoteZKP) Name() string {
	return "VERVOTE"
}

func (c *verifyVoteZKP) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *verifyVoteZKP) Run(input []byte) ([]byte, error) {	
	var cInput *C.uint8_t
	if len(input) > 0 {
		cInput = (*C.uint8_t)(&input[0])
	}

	result := C.verify_vote(cInput, C.uintptr_t(len(input)))
	
	return DecodeByteBuffer(result)
}

type verifySignature struct {}

func (c *verifySignature) Name() string {
	return "VERSIG"
}

func (c *verifySignature) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *verifySignature) Run(input []byte) ([]byte, error) {	
	var cInput *C.uint8_t
	if len(input) > 0 {
		cInput = (*C.uint8_t)(&input[0])
	}

	result := C.verify_signature(cInput, C.uintptr_t(len(input)))
	
	return DecodeByteBuffer(result)
}
