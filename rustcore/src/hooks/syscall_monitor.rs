// src/hooks/syscall_monitor.rs
use anyhow::{Context, Result};
use frida_gum::{ Gum, Module, NativeFunction, NativePointer };
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::collectors::{DataEvent, EventData};

pub struct SyscallMonitor {
    gum: Arc<Gum>,
    hooks: HashMap<String, Hook>,
    event_sender: mpsc::Sender<DataEvent>,
    enabled_hooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    pub name: String,
    pub module: String,
    pub function: String,
    pub on_enter: bool,
    pub on_leave: bool,
    pub arguments: Vec<HookArgument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookArgument {
    pub index: usize,
    pub name: String,
    pub data_type: String,
}

impl SyscallMonitor {
    pub fn new(event_sender: mpsc::Sender<DataEvent>) -> Result<Self> {
        let gum = Arc::new(Gum::obtain()?);
        
        Ok(Self {
            gum,
            hooks: HashMap::new(),
            event_sender,
            enabled_hooks: vec![
                "NtCreateFile".to_string(),
                "NtWriteFile".to_string(),
                "NtReadFile".to_string(),
                "NtAllocateVirtualMemory".to_string(),
                "NtProtectVirtualMemory".to_string(),
                "NtCreateThreadEx".to_string(),
                "NtQueueApcThread".to_string(),
                "NtCreateSection".to_string(),
                "NtMapViewOfSection".to_string(),
                "NtUnmapViewOfSection".to_string(),
            ],
        })
    }

    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing syscall monitor");

        // Define hooks for common exploit techniques
        self.add_hook(Hook {
            name: "NtCreateFile".to_string(),
            module: "ntdll.dll".to_string(),
            function: "NtCreateFile".to_string(),
            on_enter: true,
            on_leave: true,
            arguments: vec![
                HookArgument {
                    index: 0,
                    name: "FileHandle".to_string(),
                    data_type: "PHANDLE".to_string(),
                },
                HookArgument {
                    index: 1,
                    name: "DesiredAccess".to_string(),
                    data_type: "ACCESS_MASK".to_string(),
                },
                HookArgument {
                    index: 2,
                    name: "ObjectAttributes".to_string(),
                    data_type: "POBJECT_ATTRIBUTES".to_string(),
                },
            ],
        })?;

        self.add_hook(Hook {
            name: "NtAllocateVirtualMemory".to_string(),
            module: "ntdll.dll".to_string(),
            function: "NtAllocateVirtualMemory".to_string(),
            on_enter: true,
            on_leave: true,
            arguments: vec![
                HookArgument {
                    index: 0,
                    name: "ProcessHandle".to_string(),
                    data_type: "HANDLE".to_string(),
                },
                HookArgument {
                    index: 1,
                    name: "BaseAddress".to_string(),
                    data_type: "PVOID*".to_string(),
                },
                HookArgument {
                    index: 2,
                    name: "ZeroBits".to_string(),
                    data_type: "ULONG_PTR".to_string(),
                },
                HookArgument {
                    index: 3,
                    name: "RegionSize".to_string(),
                    data_type: "PSIZE_T".to_string(),
                },
                HookArgument {
                    index: 4,
                    name: "AllocationType".to_string(),
                    data_type: "ULONG".to_string(),
                },
                HookArgument {
                    index: 5,
                    name: "Protect".to_string(),
                    data_type: "ULONG".to_string(),
                },
            ],
        })?;

        self.add_hook(Hook {
            name: "NtCreateThreadEx".to_string(),
            module: "ntdll.dll".to_string(),
            function: "NtCreateThreadEx".to_string(),
            on_enter: true,
            on_leave: true,
            arguments: vec![
                HookArgument {
                    index: 0,
                    name: "ThreadHandle".to_string(),
                    data_type: "PHANDLE".to_string(),
                },
                HookArgument {
                    index: 1,
                    name: "DesiredAccess".to_string(),
                    data_type: "ACCESS_MASK".to_string(),
                },
                HookArgument {
                    index: 2,
                    name: "ObjectAttributes".to_string(),
                    data_type: "POBJECT_ATTRIBUTES".to_string(),
                },
                HookArgument {
                    index: 3,
                    name: "ProcessHandle".to_string(),
                    data_type: "HANDLE".to_string(),
                },
                HookArgument {
                    index: 4,
                    name: "StartRoutine".to_string(),
                    data_type: "PVOID".to_string(),
                },
                HookArgument {
                    index: 5,
                    name: "Argument".to_string(),
                    data_type: "PVOID".to_string(),
                },
            ],
        })?;

        info!("Syscall monitor initialized with {} hooks", self.hooks.len());
        Ok(())
    }

    fn add_hook(&mut self, hook: Hook) -> Result<()> {
        if !self.enabled_hooks.contains(&hook.name) {
            return Ok(());
        }

        let module = Module::from_name(&self.gum, &hook.module)?;
        let function = module.find_export_by_name(&hook.function)?;
        
        let hook_data = HookData {
            name: hook.name.clone(),
            event_sender: self.event_sender.clone(),
        };

        let interceptor = self.gum.interceptor();
        
        let listener = interceptor.attach(
            function,
            if hook.on_enter {
                Some(Self::on_enter)
            } else {
                None
            },
            if hook.on_leave {
                Some(Self::on_leave)
            } else {
                None
            },
            hook_data,
        )?;

        self.hooks.insert(hook.name.clone(), Hook {
            name: hook.name,
            module: hook.module,
            function: hook.function,
            on_enter: hook.on_enter,
            on_leave: hook.on_leave,
            arguments: hook.arguments,
        });

        info!("Hooked {}: {}", hook.module, hook.function);
        Ok(())
    }

    extern "C" fn on_enter(
        hook_context: &frida_gum::HookContext,
        hook_data: &mut HookData,
    ) {
        let function_address = hook_context.thread_context.pc as usize;
        
        // Create syscall event
        let event = DataEvent {
            event_id: uuid::Uuid::new_v4(),
            event_type: "syscall".to_string(),
            timestamp: chrono::Utc::now(),
            data: EventData::Syscall {
                function_name: hook_data.name.clone(),
                address: function_address,
                direction: "enter".to_string(),
                arguments: Self::extract_arguments(hook_context),
                thread_id: std::thread::current().id().as_u64().get(),
                process_id: std::process::id(),
            },
        };

        // Send event
        if let Err(e) = hook_data.event_sender.blocking_send(event) {
            error!("Failed to send syscall event: {}", e);
        }
    }

    extern "C" fn on_leave(
        hook_context: &frida_gum::HookContext,
        hook_data: &mut HookData,
    ) {
        let function_address = hook_context.thread_context.pc as usize;
        
        // Create syscall event
        let event = DataEvent {
            event_id: uuid::Uuid::new_v4(),
            event_type: "syscall".to_string(),
            timestamp: chrono::Utc::now(),
            data: EventData::Syscall {
                function_name: hook_data.name.clone(),
                address: function_address,
                direction: "leave".to_string(),
                arguments: Self::extract_arguments(hook_context),
                thread_id: std::thread::current().id().as_u64().get(),
                process_id: std::process::id(),
            },
        };

        // Send event
        if let Err(e) = hook_data.event_sender.blocking_send(event) {
            error!("Failed to send syscall event: {}", e);
        }
    }

    fn extract_arguments(hook_context: &frida_gum::HookContext) -> Vec<(String, String)> {
        let mut arguments = Vec::new();
        
        // Extract CPU registers which contain function arguments
        let context = &hook_context.thread_context;
        
        // This is a simplified implementation
        // In a real implementation, you would need to handle different calling conventions
        arguments.push(("rcx".to_string(), format!("{:x}", context.rcx)));
        arguments.push(("rdx".to_string(), format!("{:x}", context.rdx)));
        arguments.push(("r8".to_string(), format!("{:x}", context.r8)));
        arguments.push(("r9".to_string(), format!("{:x}", context.r9)));
        
        arguments
    }
}

#[derive(Debug)]
struct HookData {
    name: String,
    event_sender: mpsc::Sender<DataEvent>,
}