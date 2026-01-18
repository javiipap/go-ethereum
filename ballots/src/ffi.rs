#[repr(C)]
pub struct ByteBuffer {
    pub ptr: *mut u8,
    pub length: usize,
    pub capacity: usize,
}

impl ByteBuffer {
    pub fn from(mut data: Vec<u8>) -> Self {
        let result = Self {
            ptr: data.as_mut_ptr(),
            length: data.len(),
            capacity: data.capacity(),
        };

        std::mem::forget(data);
        result
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn empty_buffer(buffer: ByteBuffer) {
    unsafe {
        let _ = Vec::from_raw_parts(buffer.ptr, buffer.length, buffer.capacity);
    }
}

pub fn parse_vector(buffer: *const u8, length: usize) -> Vec<u8> {
    use std::slice;

    unsafe {
        if buffer.is_null() {
            Vec::new()
        } else {
            Vec::from(slice::from_raw_parts(buffer, length))
        }
    }
}
