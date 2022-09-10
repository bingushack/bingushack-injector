use std::path::Path;
use core::mem;
use widestring::WideCString;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE};
use winapi::um::winuser::{FindWindowA, GetWindowThreadProcessId};
use winapi::_core::ptr::null_mut;
use std::ffi::CString;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::shared::minwindef::{HMODULE, FARPROC, BOOL, DWORD, FALSE, LPVOID};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use std::os::windows::ffi::OsStrExt;
use winapi::shared::basetsd::SIZE_T;
use winapi::um::handleapi::CloseHandle;
use winapi::ctypes::c_void;
use winapi::um::winbase::INFINITE;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::shared::windef::HWND;
#[cfg(not(target_os = "windows"))]
compile_error!("this only works for windows");


fn obtain_handle_and_pid() -> HANDLE {
    let mut process_id: u32 = 0;
    let process_id_ptr: *mut u32 = &mut process_id;

    unsafe {
        let one_18_2 = CString::new("Minecraft 1.18.2").unwrap();
        // this is ugly
        let mut hwnd: HWND = FindWindowA(
            null_mut(),
            one_18_2.as_ptr(),
        );
        let one_18_2_multiplayer = CString::new("Minecraft 1.18.2 - Multiplayer (3rd-party Server)").unwrap();
        if hwnd == null_mut() {
            hwnd = FindWindowA(
                null_mut(),
                one_18_2_multiplayer.as_ptr(),
            );
        }
        let one_18_2_singleplayer = CString::new("Minecraft 1.18.2 - Singleplayer").unwrap();
        if hwnd == null_mut() {
            hwnd = FindWindowA(
                null_mut(),
                one_18_2_singleplayer.as_ptr(),
            );
        }
        if hwnd == null_mut() {
            panic!("cannot find the Minecraft process.")
        }

        GetWindowThreadProcessId(hwnd, process_id_ptr);

        OpenProcess(PROCESS_ALL_ACCESS, i32::from(false), *process_id_ptr)
    }
}


// credits: https://github.com/amcarthur/hammer/blob/master/src/main.rs
fn inject_library(process_handle: HANDLE, dll_path: &Path) -> bool {

    if process_handle == null_mut() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    let kernel32_module: HMODULE;
    let load_library_address: FARPROC;
    let remote_string: *mut c_void;

    let kernel32_str = WideCString::from_str("Kernel32.dll").unwrap();
    let load_library_str = CString::new("LoadLibraryW").unwrap();

    unsafe {
        kernel32_module = GetModuleHandleW(kernel32_str.as_ptr());
    }

    if kernel32_module == null_mut() {
        println!("Failed to find {:?}.", kernel32_str.to_string().unwrap());
        return false;
    }

    unsafe {
        load_library_address = GetProcAddress(kernel32_module, load_library_str.as_ptr());
    }

    if load_library_address == null_mut() {
        println!("Failed to find {:?}.", load_library_str);
        return false;
    }

    let dll_path_str = dll_path.as_os_str();
    let dll_path_size: u64 = ((dll_path_str.len() + 1) * mem::size_of::<u16>()) as u64;

    unsafe {
        remote_string = VirtualAllocEx(process_handle, null_mut(), dll_path_size as usize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    if remote_string == null_mut() {
        println!("Failed to allocate memory in the target process.");
        return false;
    }

    let mut bytes_written: SIZE_T = 0;
    let bytes_written_ptr: *mut SIZE_T = &mut bytes_written as *mut _ as *mut SIZE_T;
    let wpm_ret: BOOL;

    unsafe {
        wpm_ret = WriteProcessMemory(process_handle, remote_string, dll_path_str.encode_wide().collect::<Vec<_>>().as_ptr() as *const c_void, dll_path_size as usize, bytes_written_ptr);
    }

    if wpm_ret == FALSE || bytes_written < dll_path_size as usize {
        println!("Failed to write memory to the target process.");
        unsafe {
            VirtualFreeEx(process_handle, remote_string, dll_path_size as usize, MEM_RELEASE);
        }
        return false;
    }

    let mut thread_id: DWORD = 0;
    let thread_id_ptr: *mut DWORD = &mut thread_id as *mut _ as *mut DWORD;

    let start_routine = if load_library_address.is_null() { None } else { unsafe {Some(mem::transmute::<*const c_void, unsafe extern "system" fn(lpThreadParameter: LPVOID) -> DWORD>(load_library_address as *const c_void)) } };

    let thread_handle: HANDLE;
    unsafe {
        thread_handle = CreateRemoteThread(process_handle, null_mut(), 0, start_routine, remote_string, 0, thread_id_ptr);
    }

    if thread_handle == null_mut() {
        println!("Failed to inject the dll.");
        unsafe {
            VirtualFreeEx(process_handle, remote_string, dll_path_size as usize, MEM_RELEASE);
        }
        return false;
    }

    unsafe {
        WaitForSingleObject(thread_handle, INFINITE);
        CloseHandle(thread_handle);
        VirtualFreeEx(process_handle, remote_string, dll_path_size as usize, MEM_RELEASE);
    }
    return true;
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 2 {
        panic!("provide the directory of your dll and nothing else.")
    }
    let dll_path = std::env::current_dir().unwrap().join(Path::new( arguments.get(1).unwrap()));

    let handle = obtain_handle_and_pid();
    let injected = inject_library(handle, dll_path.as_path());
    if injected {
        println!("\ninjected.\n");
    } else {
        panic!("failed to inject. make sure game is running.")
    }

    unsafe {
        CloseHandle(handle);
    }

    println!("press down arrow to eject");
}
