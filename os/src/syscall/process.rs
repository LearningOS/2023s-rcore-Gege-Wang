//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
   /* mm::{successful_map,successful_unmap, tran_vir_to_phy, PhysAddr, VirtAddr},*/
    mm::*,
    task::{
        change_program_brk,current_user_token,exit_current_and_run_next, get_current_task_state, get_init_time, get_tcb_syscall_times, suspend_current_and_run_next, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let token = current_user_token();//当前多级页表的根节点所在的物理页号
    let vaddr:VirtAddr = (_ts as usize).into();
    let offset = vaddr.page_offset();
    let ppn = tran_vir_to_phy(token, vaddr);
    let start_addr = PhysAddr::from(ppn);
    let phy_addr = PhysAddr::from(usize::from(start_addr) + offset);
    let us = get_time_us();
    let tv = phy_addr.get_mut::<TimeVal>();
    *tv = TimeVal {
        sec:us / 1_000_000,
        usec:us % 1_000_000,
    };
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let status = get_current_task_state();
    let time = get_time_ms() -  get_init_time();
    let syscall_times = get_tcb_syscall_times();
    let token = current_user_token();

    let vaddr: VirtAddr = (_ti as usize).into();
    let offset = vaddr.page_offset();
    let ppn = tran_vir_to_phy(token,vaddr);
    let start_addr = PhysAddr::from(ppn);
    let phy_addr = PhysAddr::from(usize::from(start_addr) + offset);
    let ti = phy_addr.get_mut::<TaskInfo>();
    *ti = TaskInfo{
        status,
        syscall_times,
        time,
    };
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap");
    //未按页对齐
    if _start % 4096 != 0 {
        return -1;
    }
    if (_port & !0x7 != 0) || (_port & 0x7 == 0) {
        return -1;
    }

    if successful_map(_start, _len, _port){
        0
    }else{
        -1
    }
    
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    let token = current_user_token();
    if successful_unmap(token,_start, _len) {
        0
    }else{
        -1
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
