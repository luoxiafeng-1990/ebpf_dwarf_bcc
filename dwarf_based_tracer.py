#!/usr/bin/env python3
"""
TacoSys内核模块DWARF精确调试跟踪器
基于DWARF信息解析，跟踪用户断点处的函数和变量
"""

from bcc import BPF
import argparse
import signal
import sys
import time
import os
from datetime import datetime

# DWARF解析的函数和变量位置信息
DWARF_PRECISE_INFO = {
    "mmz_param_parse": {
        "dwarf_offset": 0x9b9b,
        "address_offset": 0x8,
        "size": 0x286,
        "decl_line": 18,
        "variables": {
            "ret": {
                "dwarf_offset": 0x9bbd,
                "decl_line": 19,
                "type": "int",
                "location": "const_value:0"
            },
            "base_ctx_ptr": {
                "dwarf_offset": 0x9bca,
                "decl_line": 25,
                "type": "BASE_DRV_CONTEXT_T*",
                "location": "location_list:0x2b"
            },
            "mmz_str": {
                "dwarf_offset": 0x9bd9,
                "decl_line": 26,
                "type": "char*",
                "location": "location_list:0x4c"
            },
            "token": {
                "dwarf_offset": 0x9be8,
                "decl_line": 27,
                "type": "char*",
                "location": "location_list:0x6f"
            },
            "cur": {
                "dwarf_offset": 0x9bf7,
                "decl_line": 28,
                "type": "char*",
                "location": "fbreg:-176"
            },
            "i": {
                "dwarf_offset": 0x9c06,
                "decl_line": 29,
                "type": "int",
                "location": "location_list:0x99"
            },
            "anonymous_index": {
                "dwarf_offset": 0x9c12,
                "decl_line": 30,
                "type": "int",
                "location": "location_list:0xc6"
            }
        }
    },
    "base_mod_init": {
        "dwarf_offset": 0x9b36,
        "address_offset": 0x8,
        "size": 0x42,
        "decl_line": 88,
        "variables": {
            "ret": {
                "dwarf_offset": 0x9b58,
                "decl_line": 90,
                "type": "int",
                "location": "location_list"
            }
        }
    },
    "base_mod_exit": {
        "dwarf_offset": 0x9b0a,
        "address_offset": 0x0,
        "size": 0x18,
        "decl_line": 109,
        "variables": {}
    }
}

# 用户断点映射
USER_BREAKPOINTS = [
    {"line": 18, "function": "mmz_param_parse", "vars": ["mmz"]},
    {"line": 19, "function": "mmz_param_parse", "vars": ["mmz", "ret"]},
    {"line": 26, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "ret"]},
    {"line": 27, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "ret"]},
    {"line": 28, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "ret"]},
    {"line": 29, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "cur", "i", "ret"]},
    {"line": 30, "function": "mmz_param_parse", "vars": ["base_ctx_ptr", "mmz_str", "token", "cur", "i", "anonymous_index", "ret"]},
    {"line": 38, "function": "mmz_param_parse", "vars": ["mmz_str", "mmz", "ret"]},
    {"line": 44, "function": "mmz_param_parse", "vars": ["cur", "mmz_str", "ret"]},
    {"line": 90, "function": "base_mod_init", "vars": ["ret"]},
    {"line": 96, "function": "base_mod_init", "vars": ["ret"]},
    {"line": 111, "function": "base_mod_exit", "vars": []}
]

# 极简安全的eBPF程序 - 添加大量调试信息
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 最简单的事件结构
struct debug_event_t {
    u32 pid;
    u64 ts;
    u32 function_id;  // 用数字代替字符串，更安全
};

BPF_PERF_OUTPUT(breakpoint_events);

// 严格的事件频率限制
BPF_ARRAY(event_limiter, u64, 1);

static inline int should_trace() {
    u32 key = 0;
    u64 *counter = event_limiter.lookup(&key);
    if (!counter) {
        return 0;
    }
    
    u64 current_time = bpf_ktime_get_ns();
    u64 last_time = *counter;
    
    // 严格限制：每2秒最多1个事件
    if (current_time - last_time < 2000000000ULL) {
        return 0;
    }
    
    event_limiter.update(&key, &current_time);
    return 1;
}

// 只跟踪一个函数，最简单最安全
int trace_base_mod_init_entry(struct pt_regs *ctx) {
    // 严格的频率和安全检查
    if (!should_trace()) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid == 0) {
        return 0;
    }
    
    struct debug_event_t data = {};
    data.pid = pid_tgid >> 32;
    data.ts = bpf_ktime_get_ns();
    data.function_id = 1;  // base_mod_init = 1
    
    breakpoint_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class DwarfBasedTracer:
    def __init__(self):
        self.bpf = None
        self.start_time = time.time()
        self.event_count = 0
        
    def load_bpf_program(self):
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            print("✓ eBPF程序加载成功")
            return True
        except Exception as e:
            print(f"✗ eBPF程序加载失败: {e}")
            return False
    
    def attach_kprobes(self):
        print("[DEBUG] 开始附加kprobe...")
        try:
            # 只附加一个最简单的kprobe
            self.bpf.attach_kprobe(event="base_mod_init", fn_name="trace_base_mod_init_entry")
            print("[DEBUG] ✓ 成功附加kprobe到 base_mod_init")
            return True
        except Exception as e:
            print(f"[DEBUG] kprobe附加失败: {e}")
            return False
    
    def print_event(self, cpu, data, size):
        print("[DEBUG] 进入事件处理回调...")
        try:
            event = self.bpf["breakpoint_events"].event(data)
            self.event_count += 1
            
            # 函数ID映射
            function_names = {1: "base_mod_init"}
            function_name = function_names.get(event.function_id, "unknown")
            
            print(f"\n\n[DEBUG] >>> 事件 #{self.event_count:04d} <<<")
            print(f"[DEBUG] 函数: {function_name}")
            print(f"[DEBUG] PID: {event.pid}")
            print(f"[DEBUG] 时间戳: {event.ts}")
            print("[DEBUG] 事件处理完成")
            
        except Exception as e:
            print(f"[DEBUG] 事件处理异常: {e}")
            import traceback
            traceback.print_exc()
    
    def run(self):
        print("TacoSys DWARF精确调试跟踪器")
        print(f"目标模块: tacosys.ko | 用户断点数量: {len(USER_BREAKPOINTS)}")
        
        print(f"\nDWARF解析的函数信息:")
        for func_name, info in DWARF_PRECISE_INFO.items():
            print(f"  {func_name}: 偏移=0x{info['dwarf_offset']:x}, 行={info['decl_line']}, 变量={len(info['variables'])}个")
        
        if not self.load_bpf_program():
            return False
        
        # 设置5分钟超时
        timeout_seconds = 5 * 60  # 5分钟
        start_time = time.time()
        kprobes_attached = False
        last_retry_time = 0
        
        print(f"\n开始跟踪... (按Ctrl+C停止)")
        print("等待tacosys.ko模块加载...")
        print("超时时间: 5分钟 (如果没有检测到ko加载将自动退出)\n")
        
        try:
            while True:
                current_time = time.time()
                elapsed_time = current_time - start_time
                
                # 检查是否超时
                if elapsed_time >= timeout_seconds:
                    print(f"\n\n超时退出: 已等待{timeout_seconds//60}分钟，未检测到ko加载事件")
                    print(f"总事件数: {self.event_count}")
                    return True
                
                # 如果kprobe还没有附加成功，每10秒重试一次
                if not kprobes_attached and (current_time - last_retry_time) >= 10:
                    print(f"尝试附加kprobe... (已等待{int(elapsed_time)}秒)")
                    if self.attach_kprobes():
                        kprobes_attached = True
                        self.bpf["breakpoint_events"].open_perf_buffer(self.print_event)
                        print("kprobe附加成功，开始监听事件...")
                    else:
                        remaining_time = timeout_seconds - elapsed_time
                        print(f"kprobe附加失败，将在10秒后重试 (剩余{int(remaining_time)}秒)")
                    last_retry_time = current_time
                
                # 如果kprobe已经附加，开始监听事件
                if kprobes_attached:
                    print("[DEBUG] 开始轮询事件...")
                    try:
                        self.bpf.perf_buffer_poll(timeout=1000)  # 1秒超时
                        print("[DEBUG] 轮询完成")
                    except Exception as e:
                        print(f"[DEBUG] 轮询异常: {e}")
                        import traceback
                        traceback.print_exc()
                        time.sleep(1)
                else:
                    # 如果还没有附加成功，等待1秒
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print(f"\n\n跟踪完成 | 总事件数: {self.event_count}")
            return True
    
    def cleanup(self):
        if self.bpf:
            print("清理eBPF资源...")

def main():
    parser = argparse.ArgumentParser(description='TacoSys DWARF精确调试跟踪器')
    parser.add_argument('--show-dwarf', action='store_true', help='显示DWARF解析信息')
    parser.add_argument('--show-breakpoints', action='store_true', help='显示用户断点配置')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("错误: 需要root权限运行")
        sys.exit(1)
    
    if args.show_dwarf:
        print("DWARF解析的精确信息:")
        for func_name, info in DWARF_PRECISE_INFO.items():
            print(f"\n函数: {func_name}")
            print(f"  DWARF偏移: 0x{info['dwarf_offset']:x}")
            print(f"  地址偏移: 0x{info['address_offset']:x}")
            print(f"  大小: 0x{info['size']:x}")
            print(f"  声明行: {info['decl_line']}")
            print(f"  变量:")
            for var_name, var_info in info['variables'].items():
                print(f"    {var_name}({var_info['type']}): 行{var_info['decl_line']}, 位置={var_info['location']}")
        return
    
    if args.show_breakpoints:
        print("用户设置的断点:")
        for i, bp in enumerate(USER_BREAKPOINTS, 1):
            print(f"{i:2d}. 行{bp['line']:3d} | {bp['function']:20s} | 变量: {', '.join(bp['vars']) if bp['vars'] else '无'}")
        return
    
    def signal_handler(sig, frame):
        print("\n正在停止...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    tracer = DwarfBasedTracer()
    try:
        tracer.run()
    finally:
        tracer.cleanup()

if __name__ == "__main__":
    main()