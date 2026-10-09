"""Synthetic offline DriverEntry execution for dispatch-registration discovery.

Unicorn receives only a copy of the image and modeled kernel imports. This is a
path-discovery aid, never evidence that a real Windows device can be opened.
"""
from __future__ import annotations

import collections
import struct

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP)

PAGE = 0x1000
STUB_BASE = 0x70000000
HEAP_BASE = 0x50000000
STACK_BASE = 0x10000000
STATE_BASE = 0x60000000
STOP = 0x71000000

def align(value, size=PAGE): return (value+size-1)&~(size-1)

def emulate_registration(image, max_instructions=30000):
    """Return witnessed MajorFunction targets under explicit synthetic API assumptions."""
    output={'status':'NOT_RUN','device_control_dispatch_rvas':[],
            'create_dispatch_rvas':[],'instructions':0,'import_calls':{},
            'model':'One synthetic successful-import DriverEntry execution; offline only; not proof of live registration.'}
    try:
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        mapped=image.pe.get_memory_mapped_image()
        uc.mem_map(image.base,align(max(image.pe.OPTIONAL_HEADER.SizeOfImage,len(mapped))))
        uc.mem_write(image.base,mapped)
        uc.mem_map(STUB_BASE,align(max(PAGE,16*(len(image.imports)+1))))
        uc.mem_write(STUB_BASE,b'\xc3'*align(max(PAGE,16*(len(image.imports)+1))))
        uc.mem_map(STOP,PAGE); uc.mem_write(STOP,b'\xf4')
        uc.mem_map(STACK_BASE,0x100000)
        uc.mem_map(STATE_BASE,0x100000)
        names={}
        for index,(address,name) in enumerate(image.imports.items()):
            stub=STUB_BASE+16*index
            names[stub]=name
            uc.mem_write(address,struct.pack('<Q',stub))
        config=getattr(getattr(image.pe,'DIRECTORY_ENTRY_LOAD_CONFIG',None),'struct',None)
        cookie=getattr(config,'SecurityCookie',0) if config is not None else 0
        if cookie and image.section(cookie):
            # Windows loader initializes the image cookie before DriverEntry.
            uc.mem_write(cookie,struct.pack('<Q',0x136ab4c7e2d9510f))
        heap_next=HEAP_BASE
        heap_end=HEAP_BASE+0x1000000
        uc.mem_map(HEAP_BASE,0x1000000)
        driver=STATE_BASE+0x1000
        registry=STATE_BASE+0x2000
        driver_extension=STATE_BASE+0x3000
        uc.mem_write(driver+0x30,struct.pack('<Q',driver_extension))
        uc.mem_write(driver_extension+8,struct.pack('<Q',driver))
        dev_next=STATE_BASE+0x10000
        stack_top=STACK_BASE+0xff000
        rsp=stack_top-8
        uc.mem_write(rsp,struct.pack('<Q',STOP))
        uc.reg_write(UC_X86_REG_RSP,rsp)
        uc.reg_write(UC_X86_REG_RCX,driver)
        uc.reg_write(UC_X86_REG_RDX,registry)
        counts=collections.Counter()
        next_stub=STUB_BASE+16*(len(names)+1)

        def getq(address): return struct.unpack('<Q',uc.mem_read(address,8))[0]
        def putq(address,value): uc.mem_write(address,struct.pack('<Q',value&0xffffffffffffffff))
        def stack_arg(n): return getq(uc.reg_read(UC_X86_REG_RSP)+8+8*n)
        def allocate(size):
            nonlocal heap_next
            size=align(max(int(size),1),16)
            if heap_next+size>heap_end: raise MemoryError('synthetic heap exhausted')
            result=heap_next; heap_next+=size
            return result
        def device_output(n):
            nonlocal dev_next
            out=stack_arg(n)
            if out:
                device=dev_next; dev_next+=0x1000
                if dev_next>=STATE_BASE+0x100000: raise MemoryError('synthetic device state exhausted')
                putq(device+8,driver)
                putq(device+0x40,allocate(0x4000))
                putq(out,device)

        def on_code(emu,address,size,_):
            output['instructions']+=1
            if address==STOP:
                output['status']='RETURNED'; emu.emu_stop(); return
            if output['instructions']>max_instructions:
                output['status']='INSTRUCTION_LIMIT'; emu.emu_stop(); return
            name=names.get(address)
            if name is None: return
            counts[name]+=1
            rcx=emu.reg_read(UC_X86_REG_RCX); rdx=emu.reg_read(UC_X86_REG_RDX)
            r8=emu.reg_read(UC_X86_REG_R8); r9=emu.reg_read(UC_X86_REG_R9)
            value=0
            try:
                if name=='IoCreateDevice': device_output(6)
                elif name in ('WdmlibIoCreateDeviceSecure','IoCreateDeviceSecure'): device_output(8)
                elif name in ('ExAllocatePoolWithTag','ExAllocatePoolWithQuotaTag','ExAllocatePool2','ExAllocatePool3'):
                    value=allocate(rdx)
                elif name in ('RtlAllocateHeap',): value=allocate(r8)
                elif name in ('MmMapIoSpace','MmMapIoSpaceEx'): value=allocate(rdx)
                elif name=='IoGetCurrentIrpStackLocation': value=rcx+0xb8
                elif name=='KeGetCurrentIrql': value=0
                elif name=='IoIsWdmVersionAvailable': value=1
                elif name=='RtlGetVersion' and rcx:
                    uc.mem_write(rcx+4,struct.pack('<III',10,0,26100))
                    uc.mem_write(rcx+16,struct.pack('<I',2))
                elif name=='MmGetSystemRoutineAddress' and rcx:
                    try:
                        length=struct.unpack('<H',uc.mem_read(rcx,2))[0]
                        string_at=getq(rcx+8)
                        requested=bytes(uc.mem_read(string_at,min(length,256))).decode('utf-16le')
                        if requested:
                            nonlocal next_stub
                            if next_stub+16<STOP:
                                names[next_stub]=requested
                                value=next_stub; next_stub+=16
                    except (UcError,UnicodeError,struct.error): pass
                elif name=='IoGetDeviceObjectPointer':
                    putq(r8,allocate(0x100)); putq(r9,allocate(0x400))
                elif name=='ExCreateCallback' and rcx: putq(rcx,allocate(0x100))
                elif name=='ObReferenceObjectByHandle' and stack_arg(5): putq(stack_arg(5),allocate(0x100))
                elif name in ('ZwCreateKey','ZwOpenKey') and rcx: putq(rcx,allocate(0x100))
                elif name=='PsCreateSystemThread' and rcx: putq(rcx,allocate(0x100))
                elif name in ('RtlQueryRegistryValues','RtlQueryRegistryValuesEx','ZwQueryValueKey'):
                    value=0xc0000034
                elif name in ('KeQuerySystemTime','KeQuerySystemTimePrecise'):
                    if rcx: putq(rcx,0)
                elif name=='RtlInitUnicodeString' and rcx:
                    length=0
                    if rdx:
                        while length<1024 and uc.mem_read(rdx+length,2)!=b'\0\0': length+=2
                    uc.mem_write(rcx,struct.pack('<HHI',length,length+2,0))
                    putq(rcx+8,rdx)
                elif name=='RtlZeroMemory' and rcx and rdx<=0x100000:
                    uc.mem_write(rcx,b'\0'*rdx)
                elif name in ('KeBugCheck','KeBugCheckEx'):
                    output['status']='BUGCHECK_PATH'; emu.emu_stop(); return
                elif name.startswith('Wdf'):
                    output['framework_imports_unmodeled']=True
            except (UcError,MemoryError,struct.error) as exc:
                output['model_error']=f'{name}: {type(exc).__name__}: {exc}'
                output['status']='MODEL_ERROR'; emu.emu_stop(); return
            emu.reg_write(UC_X86_REG_RAX,value&0xffffffffffffffff)
            return_address=getq(emu.reg_read(UC_X86_REG_RSP))
            emu.reg_write(UC_X86_REG_RSP,emu.reg_read(UC_X86_REG_RSP)+8)
            emu.reg_write(UC_X86_REG_RIP,return_address)

        uc.hook_add(UC_HOOK_CODE,on_code)
        output['status']='RUNNING'
        try: uc.emu_start(image.entry,STOP)
        except UcError as exc:
            if output['status']=='RUNNING':
                output['status']='EMU_ERROR'; output['error']=str(exc)
                output['fault_rva']=hex(uc.reg_read(UC_X86_REG_RIP)-image.base)
        if output['status']=='RUNNING': output['status']='RETURNED'
        for major,key in ((0,'create_dispatch_rvas'),(14,'device_control_dispatch_rvas')):
            ptr=getq(driver+0x70+major*8)
            if image.executable(ptr): output[key]=[hex(ptr-image.base)]
        output['import_calls']=dict(counts)
        return output
    except (UcError,MemoryError,struct.error) as exc:
        output['status']='SETUP_ERROR'; output['error']=f'{type(exc).__name__}: {exc}'
        return output
