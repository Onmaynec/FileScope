const DPAPI_MAGIC: &[u8; 8] = b"FSDPAPI1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadProtection {
    DpapiCurrentUser,
    Plaintext,
}

pub fn is_dpapi_payload(raw: &[u8]) -> bool {
    raw.starts_with(DPAPI_MAGIC)
}

pub fn protect_payload(raw: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
    platform::protect(raw)
}

pub fn unprotect_payload(raw: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
    if !is_dpapi_payload(raw) {
        return Ok((raw.to_vec(), PayloadProtection::Plaintext));
    }
    platform::unprotect(&raw[DPAPI_MAGIC.len()..])
}

#[cfg(windows)]
mod platform {
    use std::{ffi::c_void, ptr, slice};

    use super::{PayloadProtection, DPAPI_MAGIC};

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "Crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            data_description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            data_description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    pub fn protect(raw: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
        let length = u32::try_from(raw.len()).map_err(|_| {
            "DPAPI payload превышает максимально поддерживаемый размер.".to_string()
        })?;
        let input = DataBlob {
            cb_data: length,
            pb_data: raw.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let success = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if success == 0 {
            return Err(format!(
                "Windows DPAPI CryptProtectData завершился ошибкой {}.",
                unsafe { GetLastError() }
            ));
        }
        copy_and_free(output).map(|ciphertext| {
            let mut wrapped = Vec::with_capacity(DPAPI_MAGIC.len() + ciphertext.len());
            wrapped.extend_from_slice(DPAPI_MAGIC);
            wrapped.extend_from_slice(&ciphertext);
            (wrapped, PayloadProtection::DpapiCurrentUser)
        })
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
        let length = u32::try_from(ciphertext.len()).map_err(|_| {
            "DPAPI ciphertext превышает максимально поддерживаемый размер.".to_string()
        })?;
        let input = DataBlob {
            cb_data: length,
            pb_data: ciphertext.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let success = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if success == 0 {
            return Err(format!(
                "Windows DPAPI CryptUnprotectData завершился ошибкой {}.",
                unsafe { GetLastError() }
            ));
        }
        copy_and_free(output).map(|plaintext| (plaintext, PayloadProtection::DpapiCurrentUser))
    }

    fn copy_and_free(output: DataBlob) -> Result<Vec<u8>, String> {
        if output.cb_data > 0 && output.pb_data.is_null() {
            return Err("Windows DPAPI вернул пустой указатель для непустого payload.".to_string());
        }
        let value = if output.cb_data == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() }
        };
        if !output.pb_data.is_null() {
            unsafe {
                let _ = LocalFree(output.pb_data.cast());
            }
        }
        Ok(value)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::PayloadProtection;

    pub fn protect(raw: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
        Ok((raw.to_vec(), PayloadProtection::Plaintext))
    }

    pub fn unprotect(_ciphertext: &[u8]) -> Result<(Vec<u8>, PayloadProtection), String> {
        Err("DPAPI history payload нельзя расшифровать вне Windows.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_payload_remains_readable_for_migration() {
        let raw = br#"{"storageVersion":2}"#;
        let (decoded, protection) = unprotect_payload(raw).unwrap();
        assert_eq!(decoded, raw);
        assert_eq!(protection, PayloadProtection::Plaintext);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_is_user_bound_and_does_not_store_plaintext() {
        let raw = b"FileScope DPAPI regression secret";
        let (protected, protection) = protect_payload(raw).unwrap();
        assert_eq!(protection, PayloadProtection::DpapiCurrentUser);
        assert!(is_dpapi_payload(&protected));
        assert!(!protected.windows(raw.len()).any(|window| window == raw));
        let (decoded, decoded_protection) = unprotect_payload(&protected).unwrap();
        assert_eq!(decoded_protection, PayloadProtection::DpapiCurrentUser);
        assert_eq!(decoded, raw);
    }
}
