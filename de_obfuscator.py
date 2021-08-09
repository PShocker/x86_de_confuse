# 根据capstone的ida反混淆脚本
# 依据两次写,没有读寄存器的原则对指令进行反混淆
# 例如      mov eax,esi
#           mov eax,ebp
# 等价于    mov eax,ebp



import capstone
from idaapi import *
import keypatch

patcher=keypatch.Keypatch_Asm()


md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
md.detail=True

g_cs_eax = [capstone.x86_const.X86_REG_AH, capstone.x86_const.X86_REG_AL, capstone.x86_const.X86_REG_AX]
g_cs_ebx = [capstone.x86_const.X86_REG_BH, capstone.x86_const.X86_REG_BL, capstone.x86_const.X86_REG_BX]
g_cs_ecx = [capstone.x86_const.X86_REG_CH, capstone.x86_const.X86_REG_CL, capstone.x86_const.X86_REG_CX]
g_cs_edx = [capstone.x86_const.X86_REG_DH, capstone.x86_const.X86_REG_DL, capstone.x86_const.X86_REG_DX]
g_cs_ebp = [capstone.x86_const.X86_REG_BP, capstone.x86_const.X86_REG_BPL]
g_cs_esp = [capstone.x86_const.X86_REG_SP, capstone.x86_const.X86_REG_SPL]
g_cs_esi = [capstone.x86_const.X86_REG_SI, capstone.x86_const.X86_REG_SIL]
g_cs_edi = [capstone.x86_const.X86_REG_DI, capstone.x86_const.X86_REG_DIL]

def cs_extendRegTo32bit(cs_reg):
 
    if(cs_reg in g_cs_eax):
        return capstone.x86_const.X86_REG_EAX
        
    elif(cs_reg in g_cs_ebx):
        return capstone.x86_const.X86_REG_EBX
        
    elif(cs_reg in g_cs_ecx):
        return capstone.x86_const.X86_REG_ECX 
        
    elif(cs_reg in g_cs_edx):
        return capstone.x86_const.X86_REG_EDX 
        
    elif(cs_reg in g_cs_ebp):
        return capstone.x86_const.X86_REG_EBP 
        
    elif(cs_reg in g_cs_esp):
        return capstone.x86_const.X86_REG_ESP 
        
    elif(cs_reg in g_cs_esi):
        return capstone.x86_const.X86_REG_ESI 
        
    elif(cs_reg in g_cs_edi):
        return capstone.x86_const.X86_REG_EDI   
        
    else:
        return cs_reg




regs={'eax':None,
'ecx':None,
'edx':None,
'ebx':None,
'esp':None,
'ebp':None,
'esi':None,
'edi':None,
'eflags':None,
}



def patch(addr):
    # print(regs)
    print('0x%x'%addr)
    set_color(addr, CIC_ITEM, 0x00ffff)
    # patcher.patch_code(addr,'nop',patcher.syntax,True,False)


start_addr=0x8660BF #起始地址
end_addr=0x0866155 #结束地址

codes=get_bytes(start_addr,idc.next_head(end_addr)-start_addr)
for code in md.disasm(codes,start_addr):
    readList,writeList = code.regs_access() # readList对寄存器的读,writeList对寄存器的写
    # print(code)
    for r in readList: #对寄存器的读
        # print(code.reg_name(cs_extendRegTo32bit(r)))
        reg_name=code.reg_name(cs_extendRegTo32bit(r))
        if reg_name not in regs:   #对寄存器没有读操作
            continue
        elif regs[reg_name]!=None:
            patch_addr=regs[reg_name]
            for key in regs:#说明patch_addr的指令写已经被读,判断该指令有效
                    if regs[key] == patch_addr:#将所有引用该地址的值清空
                        # print(regs)
                        regs[key]=None


    for w in writeList: #对寄存器的写
        patch_flag=True #这里是决定是否patch的标志
        reg_name=code.reg_name(cs_extendRegTo32bit(w))
        # continue
        if reg_name not in regs:   #对寄存器没有写操作,这里有可能对内存进行写,所以不处理
            continue
        elif regs[reg_name]!=None: #说明上次的写到这次的写操作之间没有读,因为如果有读操作,则regs[reg_name]为None
                patch_addr=regs[reg_name] 
                for key in regs:#判断该指令是否对多个寄存器进行了写操作
                    if key != reg_name and regs[key]==patch_addr:#说明patch_addr的指令对多个寄存器有写操作,不进行patch操作
                        patch_flag=False
                if patch_flag==True \
                and (idc.print_insn_mnem(regs[reg_name])!='call'\
                or idc.print_insn_mnem(regs[reg_name])!='push'\
                or idc.print_insn_mnem(regs[reg_name])!='pop'):
                    patch(regs[reg_name]) #排除所有的call,push,pop指令,认为其是有效指令
        regs[reg_name]=code.address

   
    