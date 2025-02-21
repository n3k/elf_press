#![no_std]
#![allow(non_camel_case_types)]

pub unsafe trait Primitive: Clone + Copy {}
unsafe impl Primitive for u8 {}
unsafe impl Primitive for u16 {}
unsafe impl Primitive for u32 {}
unsafe impl Primitive for u64 {}
unsafe impl Primitive for u128 {}
unsafe impl Primitive for usize {}
unsafe impl Primitive for i8 {}
unsafe impl Primitive for i16 {}
unsafe impl Primitive for i32 {}
unsafe impl Primitive for i64 {}
unsafe impl Primitive for i128 {}
unsafe impl Primitive for isize {}

/// To get a struct &'a T out of a &'a [u8]
pub fn from_bytearray<'a, T: Primitive>(input: &'a [u8]) -> Option<&'a T> {
    assert!(core::mem::size_of::<T>() <= input.len());
    unsafe { core::mem::transmute(input as *const [u8] as *const u8 as *const T) }
}

/// To get a &'a [u8] out of a &'a T
pub fn to_bytearray<'a, T: Primitive>(input: &'a T) -> &'a [u8] {
    unsafe { 
        core::slice::from_raw_parts(input as *const T as *const u8, core::mem::size_of::<T>())
    }    
}

