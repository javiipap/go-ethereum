use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn wrap_c_ffi(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_block = &input_fn.block;
    let fn_vis = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;

    if fn_inputs.len() != 1 {
        return syn::Error::new_spanned(
            fn_inputs,
            "La función debe tener exactamente un parámetro: data: Vec<u8>",
        )
        .to_compile_error()
        .into();
    }

    let expanded = quote! {
        #fn_vis extern "C" fn #fn_name(buffer: *const u8, length: usize) -> ByteBuffer {
            use std::slice;

            let data = unsafe {
                if buffer.is_null() {
                    Vec::new()
                } else {
                    Vec::from(slice::from_raw_parts(buffer, length))
                }
            };

            let output: Vec<u8> = (move || #fn_block)();

            ByteBuffer::from(output)
        }
    };

    expanded.into()
}
