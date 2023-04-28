//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the operating system.
//!
//! Be careful when you see `__switch` ASM function in `switch.S`. Control flow around this function
//! might not be what you expect.

mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use core::usize;

use crate::config::MAX_SYSCALL_NUM;

use crate::loader::{get_app_data, get_num_app};
use crate::mm::MapPermission;
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use alloc::vec::Vec;
use lazy_static::*;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;

/// The task manager, where all the tasks are managed.
///
/// Functions implemented on `TaskManager` deals with all task state transitions
/// and task context switching. For convenience, you can find wrappers around it
/// in the module level.
///
/// Most of `TaskManager` are hidden behind the field `inner`, to defer
/// borrowing checks to runtime. You can see examples on how to use `inner` in
/// existing functions on `TaskManager`.
pub struct TaskManager {
    /// total number of tasks
    num_app: usize,
    /// use inner value to get mutable access
    inner: UPSafeCell<TaskManagerInner>,
}

/// The task manager inner in 'UPSafeCell'
struct TaskManagerInner {
    /// task list
    tasks: Vec<TaskControlBlock>,
    /// id of current `Running` task
    current_task: usize,
    /// avoid repeat alloc
    vec_for_alloc: Vec<(usize, usize)>,
}

lazy_static! {
    /// a `TaskManager` global instance through lazy_static!
    pub static ref TASK_MANAGER: TaskManager = {
        println!("init TASK_MANAGER");
        let num_app = get_num_app();
        println!("num_app = {}", num_app);
        let mut tasks: Vec<TaskControlBlock> = Vec::new();
        for i in 0..num_app {
            tasks.push(TaskControlBlock::new(get_app_data(i), i));
        }
        let vec_for_alloc: Vec<(usize, usize)> = Vec::new();
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                    vec_for_alloc,
                })
            },
        }
    };
}

impl TaskManager {
    /// Run the first task in task list.
    ///
    /// Generally, the first task in task list is an idle task (we call it zero process later).
    /// But in ch4, we load apps statically, so the first task is a real app.
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next_task = &mut inner.tasks[0];
        next_task.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(&mut _unused as *mut _, next_task_cx_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    /// Change the status of current `Running` task into `Ready`.
    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Ready;
    }

    /// Change the status of current `Running` task into `Exited`.
    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].task_status = TaskStatus::Exited;
    }

    /// Find next task to run and return task id.
    ///
    /// In this case, we only return the first `Ready` task in task list.
    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    /// Get the current 'Running' task's token.
    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_user_token()
    }

    ///Get memory_set
    fn append_to_memset(&self, start: usize, new_end: usize) -> bool {
        let mut inner  = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur]
            .memory_set
            .append_to(start.into(),new_end.into())
    }

    ///Remove memory_set
    fn remove_from_memset(&self, start: usize, new_end: usize) -> bool {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur]
            .memory_set
            .shrink_to(start.into(), new_end.into())
    }

    ///Push
    fn push(&self, start: usize, end: usize, permission: MapPermission) -> bool {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;

        let mut cp_vec = inner.vec_for_alloc.clone();

        while !cp_vec.is_empty() {
            let (beg, en) = cp_vec.pop().unwrap();
            if !((start < beg && end <= beg) || (start >= en && end >en)) {
                return false;
            }
        }
        inner.vec_for_alloc.push((start, end));
        inner.tasks[cur]
            .memory_set
            .insert_framed_area(start.into(), end.into(), permission);
        true
    }
    ///Return 
    pub fn pay_back(&self, start: usize, end: usize){
        let mut inner = self.inner.exclusive_access();
        let mut index:usize = 0;
        let mut cp_vec = inner.vec_for_alloc.clone();
        cp_vec.reverse();
        inner.vec_for_alloc.reverse();
        while !cp_vec.is_empty(){
            index += 1;
            let (beg, en) = cp_vec.pop().unwrap();
            if beg >= start && en <= end{
                if beg == start && en == end{
                    inner.vec_for_alloc.remove(index);
                }
            }
             inner.vec_for_alloc.reverse();
             return
        }
    }

    /// Get the current 'Running' task's trap contexts.
    fn get_current_trap_cx(&self) -> &'static mut TrapContext {
        let inner = self.inner.exclusive_access();
        inner.tasks[inner.current_task].get_trap_cx()
    }

    /// Change the current 'Running' task's program break
    pub fn change_current_program_brk(&self, size: i32) -> Option<usize> {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        inner.tasks[cur].change_program_brk(size)
    }

    /// Switch current `Running` task to the task we have found,
    /// or there is no `Ready` task and we can exit with all applications completed
    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }
    fn get_current_task_state(&self) -> TaskStatus {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status
    }

    fn get_init_time(&self) -> usize{
        let inner = self.inner.exclusive_access();
        inner.tasks[0].time
    }

    fn get_tcb_syscall_times(&self) -> [u32; MAX_SYSCALL_NUM] {
        let inner  = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].tcb_syscall_times
    }
    
    fn set_tcb_syscall_times(&self, syscall_id: usize) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].tcb_syscall_times[syscall_id] += 1;
    }

}

/// Run the first task in task list.
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// Switch current `Running` task to the task we have found,
/// or there is no `Ready` task and we can exit with all applications completed
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// Change the status of current `Running` task into `Ready`.
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// Change the status of current `Running` task into `Exited`.
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// Suspend the current 'Running' task and run the next task in task list.
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

/// Get the current 'Running' task's token.
pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

/// Get the current 'Running' task's trap contexts.
pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

/// Change the current 'Running' task's program break
pub fn change_program_brk(size: i32) -> Option<usize> {
    TASK_MANAGER.change_current_program_brk(size)
}
/// get memory set
pub fn append_to_memset(start: usize, end: usize) -> bool {
    TASK_MANAGER.append_to_memset(start, end)
}

/// push
pub fn push(start: usize, end: usize, permission: MapPermission) -> bool {
    TASK_MANAGER.push(start, end, permission)
}

/// pop
pub fn remove_from_memset(begin: usize, end: usize) -> bool {
    TASK_MANAGER.remove_from_memset(begin, end)
}

/// pay
pub fn pay_back(begin: usize, end: usize) {
    TASK_MANAGER.pay_back(begin, end);
}

/// get state
pub fn get_current_task_state() -> TaskStatus{
    TASK_MANAGER.get_current_task_state()
}

/// get the init time
pub fn get_init_time() -> usize {
    TASK_MANAGER.get_init_time()
}

/// get tcb syscall times
pub fn get_tcb_syscall_times() -> [u32; MAX_SYSCALL_NUM] {
    TASK_MANAGER.get_tcb_syscall_times()
}

/// set tcb syscall times
pub fn set_tcb_syscall_times(syscall_id : usize) {
    TASK_MANAGER.set_tcb_syscall_times(syscall_id);
}
