use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("favicon.ico");  // 设置应用程序图标
        res.compile().unwrap();
    }
}
