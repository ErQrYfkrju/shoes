//! JNI bindings for ByeByeDPI Android app.
//!
//! Package: `io.github.cfal.shoes`
//! Class: `ShoesNative`
//!
//! # Kotlin interface
//! ```kotlin
//! class ShoesNative {
//!     companion object { init { System.loadLibrary("shoes") } }
//!
//!     private external fun jniInit(logLevel: String): Int
//!     private external fun jniStart(configYaml: String, protectCallback: Any?): Long
//!     private external fun jniStop(handle: Long)
//!     private external fun jniIsRunning(): Boolean
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::Ordering;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use log::{Record, error, info};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::logging::{DynamicFileLogWriter, LogWriter};
use crate::tun::{FnSocketProtector, set_global_socket_protector};

use super::common::{
    self, LOG_FILE, LOGGER_INITIALIZED, TUN_SERVICE, TunServiceHandle, setup_log_file,
    start_proxy_from_config,
};

/// Пишет в Android logcat.
struct LogcatWriter;

impl LogWriter for LogcatWriter {
    fn write_log(&self, record: &Record, _formatted: &str) {
        #[cfg(target_os = "android")]
        {
            use std::ffi::CString;
            let tag = CString::new("shoes").unwrap_or_default();
            let msg = CString::new(format!("{}", record.args())).unwrap_or_default();
            let priority = match record.level() {
                log::Level::Error => 6,
                log::Level::Warn  => 5,
                log::Level::Info  => 4,
                log::Level::Debug => 3,
                log::Level::Trace => 2,
            };
            unsafe {
                ndk_sys::__android_log_write(
                    priority as i32,
                    tag.as_ptr(),
                    msg.as_ptr(),
                );
            }
        }
        #[cfg(not(target_os = "android"))]
        let _ = record;
    }

    fn flush(&self) {}
}

/// Инициализирует библиотеку shoes.
///
/// Должна быть вызвана один раз до всех остальных функций.
/// Возвращает 0 при успехе, -1 при ошибке.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_cfal_shoes_ShoesNative_jniInit(
    mut env: JNIEnv,
    _class: JClass,
    log_level: JString,
) -> jint {
    let level_str: String = match env.get_string(&log_level) {
        Ok(s) => s.into(),
        Err(e) => {
            eprintln!("Failed to get log level string: {}", e);
            return -1;
        }
    };

    let level = crate::logging::parse_log_level(&level_str)
        .unwrap_or(log::LevelFilter::Info);

    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        LOG_FILE.get_or_init(|| parking_lot::Mutex::new(None));

        let writers: Vec<Box<dyn LogWriter>> = vec![
            Box::new(LogcatWriter),
            Box::new(DynamicFileLogWriter::new(&LOG_FILE)),
        ];
        let directives = vec![crate::logging::Directive { name: None, level }];
        crate::logging::init_multi_logger(writers, directives);
    }

    info!("shoes (ByeByeDPI) initialized, log level: {}", level_str);
    0
}

/// Запускает shoes-сервис.
///
/// * `config_yaml`      — готовый YAML-конфиг (device_fd уже подставлен Kotlin-стороной).
/// * `protect_callback` — объект с методом `protect(Int): Boolean` (VpnService в VPN-режиме)
///                        или `null` в Proxy-режиме.
///
/// Возвращает хэндл > 0 при успехе, -1 при ошибке.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_cfal_shoes_ShoesNative_jniStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_yaml: JString<'local>,
    protect_callback: JObject<'local>,
) -> jlong {
    info!("jniStart: starting shoes service");

    let config_str: String = match env.get_string(&config_yaml) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get config string: {}", e);
            return -1;
        }
    };

    // В Proxy-режиме callback == null — защищать сокеты не нужно.
    let is_vpn_mode = !protect_callback.is_null();

    if is_vpn_mode {
        let callback_ref = match env.new_global_ref(&protect_callback) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to create global ref for callback: {}", e);
                return -1;
            }
        };

        let jvm = match env.get_java_vm() {
            Ok(vm) => Arc::new(vm),
            Err(e) => {
                error!("Failed to get JavaVM: {}", e);
                return -1;
            }
        };

        let callback_ref = Arc::new(callback_ref);
        let jvm_clone = jvm.clone();
        let callback_clone = callback_ref.clone();

        let protector = FnSocketProtector::new(move |fd: i32| {
            let mut env = match jvm_clone.attach_current_thread() {
                Ok(e) => e,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to attach to JVM: {}", e),
                    ));
                }
            };

            let result = env.call_method(
                &*callback_clone,
                "protect",
                "(I)Z",
                &[JValue::Int(fd)],
            );

            match result {
                Ok(v) => {
                    if v.z().unwrap_or(false) {
                        Ok(())
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "VpnService.protect() returned false",
                        ))
                    }
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to call protect(): {}", e),
                )),
            }
        });

        set_global_socket_protector(Arc::new(protector));
    }

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    runtime.spawn(async move {
        info!("Shoes service task started");

        let result = if is_vpn_mode {
            common::start_from_config(&config_str, shutdown_rx).await
        } else {
            start_proxy_from_config(&config_str, shutdown_rx).await
        };

        match result {
            Ok(()) => info!("Shoes service stopped normally"),
            Err(e) => error!("Shoes service error: {}", e),
        }

        running_clone.store(false, Ordering::SeqCst);
    });

    let handle = TunServiceHandle {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        running,
    };

    let service = TUN_SERVICE.get_or_init(|| parking_lot::Mutex::new(None));
    *service.lock() = Some(handle);

    info!("jniStart: shoes service started");
    1
}

/// Останавливает shoes-сервис.
///
/// * `handle` — значение, возвращённое `jniStart` (зарезервировано для будущего использования).
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_cfal_shoes_ShoesNative_jniStop(
    _env: JNIEnv,
    _class: JClass,
    _handle: jlong,
) {
    info!("jniStop: stopping shoes service");
    common::stop_service();
}

/// Возвращает JNI_TRUE, если сервис запущен.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_cfal_shoes_ShoesNative_jniIsRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if common::is_service_running() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Устанавливает путь к файлу логов.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_cfal_shoes_ShoesNative_jniSetLogFile(
    mut env: JNIEnv,
    _class: JClass,
    log_path: JString,
) -> jint {
    let path_str: String = match env.get_string(&log_path) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get log path string: {}", e);
            return -1;
        }
    };

    setup_log_file(&path_str)
}
