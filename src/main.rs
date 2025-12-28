#![windows_subsystem = "windows"]

use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::ptr::null_mut;

// winapi 用于窗口管理
use winapi::um::winuser::*;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::shellapi::*;
use winapi::um::winreg::*;
use winapi::shared::windef::{HWND, HMENU, POINT};
use winapi::shared::minwindef::{WPARAM, LPARAM, LRESULT, UINT, HKEY};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::um::winnt::{KEY_READ, KEY_WRITE, REG_SZ};

// windows crate 用于通知
use windows::core::*;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager, ToastTemplateType};

// 常量定义
const WM_TRAYICON: u32 = WM_USER + 1;
const ID_TRAY_EXIT: u32 = 1001;
const ID_TRAY_AUTOSTART: u32 = 1002;
const ID_TRAYICON: u32 = 1;
const APP_NAME: &str = "WeChatNotifier";

// 全局静态变量
static SHELL_HOOK_MSG: OnceLock<u32> = OnceLock::new();
static mut LAST_NOTIFICATION_TIME: Option<Instant> = None;
static mut MAIN_HWND: HWND = null_mut();

fn main() {
    unsafe {
        // 1. 初始化 COM 库
        winapi::um::combaseapi::CoInitializeEx(null_mut(), 0);

        let instance = GetModuleHandleW(null_mut());
        let class_name = wide_string("WeChatMonitorClass");

        // 2. 注册窗口类
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: null_mut(),
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);

        // 3. 创建消息专用窗口
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide_string("WeChatMonitor").as_ptr(),
            0,
            0, 0, 0, 0,
            HWND_MESSAGE,
            null_mut(),
            instance,
            null_mut(),
        );
        MAIN_HWND = hwnd;

        // 4. 添加系统托盘图标
        add_tray_icon(hwnd);

        // 5. 注册 Shell Hook
        RegisterShellHookWindow(hwnd);

        // 6. 获取系统动态分配的消息 ID
        let msg_id = RegisterWindowMessageW(wide_string("SHELLHOOK").as_ptr());
        SHELL_HOOK_MSG.set(msg_id).unwrap();

        // 7. 进入消息循环
        let mut message: MSG = std::mem::zeroed();
        while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        // 8. 退出时移除托盘图标
        remove_tray_icon(hwnd);
    }
}

// 添加系统托盘图标
unsafe fn add_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = ID_TRAYICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    
    // 优先从 exe 嵌入的资源加载图标（资源 ID = 1）
    let instance = GetModuleHandleW(null_mut());
    nid.hIcon = LoadIconW(instance, 1 as *const u16);
    
    // 如果资源加载失败，尝试从文件加载
    if nid.hIcon.is_null() {
        let icon_path = get_exe_dir_path("favicon.ico");
        nid.hIcon = LoadImageW(
            null_mut(),
            icon_path.as_ptr(),
            IMAGE_ICON,
            0, 0,
            LR_LOADFROMFILE | LR_DEFAULTSIZE,
        ) as _;
    }
    
    // 如果仍然失败，使用系统默认图标
    if nid.hIcon.is_null() {
        nid.hIcon = LoadIconW(null_mut(), IDI_APPLICATION);
    }
    
    // 设置提示文字
    let tip = wide_string("微信消息提醒");
    for (i, &c) in tip.iter().take(127).enumerate() {
        nid.szTip[i] = c;
    }
    
    Shell_NotifyIconW(NIM_ADD, &mut nid);
}

// 获取 exe 所在目录下的文件路径
unsafe fn get_exe_dir_path(filename: &str) -> Vec<u16> {
    let mut path = [0u16; 260];
    let len = winapi::um::libloaderapi::GetModuleFileNameW(null_mut(), path.as_mut_ptr(), 260);
    
    // 找到最后一个\uff0c截断为目录
    let mut last_slash = 0;
    for i in 0..len as usize {
        if path[i] == '\\' as u16 {
            last_slash = i;
        }
    }
    
    // 拼接文件名
    let filename_wide = wide_string(filename);
    let mut result: Vec<u16> = path[..=last_slash].to_vec();
    result.extend_from_slice(&filename_wide);
    result
}

// 移除系统托盘图标
unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = ID_TRAYICON;
    Shell_NotifyIconW(NIM_DELETE, &mut nid);
}

// 显示托盘右键菜单
unsafe fn show_tray_menu(hwnd: HWND) {
    let menu: HMENU = CreatePopupMenu();
    
    // 检查当前自启动状态
    let autostart_enabled = is_autostart_enabled();
    let autostart_flags = if autostart_enabled { MF_STRING | MF_CHECKED } else { MF_STRING };
    AppendMenuW(menu, autostart_flags, ID_TRAY_AUTOSTART as ULONG_PTR, wide_string("开机自启动").as_ptr());
    AppendMenuW(menu, MF_SEPARATOR, 0, null_mut());
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT as ULONG_PTR, wide_string("退出").as_ptr());
    
    // 获取鼠标位置
    let mut pt: POINT = std::mem::zeroed();
    GetCursorPos(&mut pt);
    
    // 必须先将窗口设为前台，否则菜单可能不会消失
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON, 
                   pt.x, pt.y, 0, hwnd, null_mut());
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

// 检查是否已启用开机自启动
unsafe fn is_autostart_enabled() -> bool {
    let mut hkey: HKEY = null_mut();
    let subkey = wide_string("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    
    if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) == 0 {
        let value_name = wide_string(APP_NAME);
        let result = RegQueryValueExW(hkey, value_name.as_ptr(), null_mut(), null_mut(), null_mut(), null_mut());
        RegCloseKey(hkey);
        return result == 0;
    }
    false
}

// 设置开机自启动
unsafe fn set_autostart(enable: bool) {
    let mut hkey: HKEY = null_mut();
    let subkey = wide_string("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    
    if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_WRITE, &mut hkey) == 0 {
        let value_name = wide_string(APP_NAME);
        
        if enable {
            // 获取当前 exe 路径
            let exe_path = get_exe_path();
            RegSetValueExW(
                hkey,
                value_name.as_ptr(),
                0,
                REG_SZ,
                exe_path.as_ptr() as *const u8,
                (exe_path.len() * 2) as u32,
            );
        } else {
            RegDeleteValueW(hkey, value_name.as_ptr());
        }
        RegCloseKey(hkey);
    }
}

// 获取当前 exe 完整路径
unsafe fn get_exe_path() -> Vec<u16> {
    let mut path = [0u16; 260];
    let len = winapi::um::libloaderapi::GetModuleFileNameW(null_mut(), path.as_mut_ptr(), 260);
    path[..=len as usize].to_vec()
}

// 辅助函数：转换为宽字符串
fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// 窗口过程回调
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // 检查是否是 Shell Hook 消息
    if let Some(&hook_msg_id) = SHELL_HOOK_MSG.get() {
        if msg == hook_msg_id {
            handle_shell_hook(wparam, lparam);
            return 0;
        }
    }

    match msg {
        // 托盘图标消息
        WM_TRAYICON => {
            let event = (lparam & 0xFFFF) as u32;
            if event == WM_RBUTTONUP {
                show_tray_menu(hwnd);
            }
            0
        }
        // 菜单命令
        WM_COMMAND => {
            let cmd = (wparam & 0xFFFF) as u32;
            match cmd {
                ID_TRAY_EXIT => PostQuitMessage(0),
                ID_TRAY_AUTOSTART => {
                    let current = is_autostart_enabled();
                    set_autostart(!current);
                }
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// 处理 Shell 事件
unsafe fn handle_shell_hook(event: WPARAM, lparam: LPARAM) {
    const HSHELL_FLASH: usize = 0x8006;
    const HSHELL_RUDEFLASH: usize = HSHELL_FLASH | 0x8000;

    if event == HSHELL_FLASH || event == HSHELL_RUDEFLASH {
        let target_hwnd = lparam as HWND;
        let mut buffer = [0u16; 512];

        let len = GetWindowTextW(target_hwnd, buffer.as_mut_ptr(), 512);
        if len > 0 {
            let title = String::from_utf16_lossy(&buffer[..len as usize]);

            if title.contains("微信") || title.contains("WeChat") {
                check_and_send_toast();
            }
        }
    }
}

// 防抖动与发送逻辑
fn check_and_send_toast() {
    unsafe {
        let now = Instant::now();

        if let Some(last_time) = LAST_NOTIFICATION_TIME {
            if now.duration_since(last_time) < Duration::from_secs(5) {
                return;
            }
        }

        LAST_NOTIFICATION_TIME = Some(now);
        let _ = show_silent_toast("微信", "收到新消息");
    }
}

// 构建并显示静音通知
fn show_silent_toast(title: &str, content: &str) -> Result<()> {
    let toast_xml = ToastNotificationManager::GetTemplateContent(ToastTemplateType::ToastText02)?;

    let text_nodes = toast_xml.GetElementsByTagName(&HSTRING::from("text"))?;
    let node0 = text_nodes.Item(0)?;
    node0.SetInnerText(&HSTRING::from(title))?;
    let node1 = text_nodes.Item(1)?;
    node1.SetInnerText(&HSTRING::from(content))?;

    let toast_node = toast_xml.DocumentElement()?;
    let audio_node = toast_xml.CreateElement(&HSTRING::from("audio"))?;
    audio_node.SetAttribute(&HSTRING::from("silent"), &HSTRING::from("true"))?;
    toast_node.AppendChild(&audio_node)?;

    let notification = ToastNotification::CreateToastNotification(&toast_xml)?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from("WeChat.Silent.Notifier"))?
        .Show(&notification)?;

    Ok(())
}
