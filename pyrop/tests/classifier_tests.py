import unittest, logging
import archinfo

from rop_compiler.gadget import *
import rop_compiler.classifier as classifier

class ClassifierTests(unittest.TestCase):
    def assert_contain_this_type(self, code, expect_type, arch = archinfo.ArchX86()):
        address = 0x40000
        gadget_classifier = classifier.GadgetClassifier(arch, code, address, log_level = logging.DEBUG)
        gadgets = gadget_classifier.create_gadgets_from_instructions(address)
        types = []
        for g in gadgets:
            if g.address != address: #The gadget should be starting at the *address*
                continue
            types.append(type(g))        
        self.assertTrue(expect_type in types)
        
    def assert_not_contain_this_type(self, code, not_expect_type):
        address = 0x40000
        gadget_classifier = classifier.GadgetClassifier(archinfo.ArchX86(), code, address, log_level = logging.DEBUG)
        gadgets = gadget_classifier.create_gadgets_from_instructions(address)
        types = []
        for g in gadgets:
            if g.address != address: #The gadget should be starting at the *address*
                continue
            types.append(type(g))        
        self.assertFalse(not_expect_type in types)
    
    def test_gadget_design(self):
        #Test cases:
        #1. NOP: no operation: designed for padding
        #TRUE: ret
        code = '\xc3'
        self.assert_contain_this_type(code, NOP)

        #1. RetN: no operation: designed for allocating a private framework for next gadget
        #TRUE: ret 4
        code = '\xc2\x04\x00'
        self.assert_contain_this_type(code, RetN)
        
        #2. RegJumpNormal: IP = AddrReg + Offset: designed for invoking other gadgets
        #TRUE: jmp eax
        #TRUE: pop eax; pop ecx; push ebx; ret
        #TRUE: pop ebx; call eax
        #FALSE: jmp esp
        #FALSE: push ebx; ret          
        code = "\xff\xe0"
        self.assert_contain_this_type(code, RegJumpNormal)
        code = "\x58\x59\x53\xc3"
        self.assert_contain_this_type(code, RegJumpNormal)
        code = "\x5b\xff\xd0"
        self.assert_contain_this_type(code, RegJumpNormal)
        code = "\xff\xe4"
        self.assert_not_contain_this_type(code, RegJumpNormal)
        code = "\x53\xc3"
        self.assert_not_contain_this_type(code, RegJumpNormal)
        
        #MoveRegG: OutReg = InReg: designed for banking register values
        #TRUE: mov eax, edx; ret
        #TRUE: mov eax, esp; ret
        #FALSE: mov esp, eax; ret
        code = "\x89\xd0\xc3"
        self.assert_contain_this_type(code, MoveReg)
        code = "\x89\xe0\xc3"
        self.assert_contain_this_type(code, MoveReg)
        code = "\x89\xc4\xc3"
        self.assert_not_contain_this_type(code, MoveReg)
        
        #4. LoadConstG: OutReg = value: designed for loading 0 and other values into registers 
        #TRUE: mov ebp, 0x20 ; ret
        #FALSE: mov esp, 0x20 ; ret
        code = "\xbd\x20\x00\x00\x00\xc3"
        self.assert_contain_this_type(code, LoadConst)
        code = "\xbc\x20\x00\x00\x00\xc3"
        self.assert_not_contain_this_type(code, LoadConst)
        
        #5. LoadMemG: OutReg = M[AddrReg+Offset]: designed for setting register values, and loading temporary variables.
        #TRUE: pop ebp ; ret
        #TRUE: mov eax, [ebx+0x20]; ret
        #FALSE: mov eax, [esp+0x20]; ret    #Can hardly be used, ignore the gadget
        #FALSE: mov esp, [ebx+0x20]; ret
        #FALSE: mov esp, [esp+0x20]; ret
        code = "\x5d\xc3"
        self.assert_contain_this_type(code, LoadMem)
        code = "\x8b\x43\x20\xc3"
        self.assert_contain_this_type(code, LoadMem)
        code = "\x8b\x44\x24\x20\xc3"
        self.assert_not_contain_this_type(code, LoadMem)
        code = "\x8b\x63\x20\xc3"
        self.assert_not_contain_this_type(code, LoadMem)
        code = "\x8b\x64\x24\x20\xc3"
        self.assert_not_contain_this_type(code, LoadMem)

        #6. StoreMemG: M[AddrReg+Offset] = InReg: designed for saving temporary variables.
        #TRUE: mov [ebx + 0x40], eax ; ret
        #TRUE: mov [ebx + 0x40], esp ; ret
        #TRUE: mov [esp + 0x40], eax ; ret      
        code = "\x89\x43\x40\xc3"
        self.assert_contain_this_type(code, StoreMem)
        code = "\x89\x63\x40\xc3"
        self.assert_contain_this_type(code, StoreMem)
        code = "\x89\x44\x24\x40\xc3"
        self.assert_contain_this_type(code, StoreMem)
        #FALSE: push eax ; mov eax, ebp ; pop ebx ; pop ebp ; ret
        code = "\x50\x89\xe8\x5b\x5d\xc3"
        self.assert_not_contain_this_type(code, StoreMem)
        

        #7. ArithmeticG: OutReg = InReg * InReg2: designed for conducting arithmetic operation on registers
        #TRUE: add eax, ebx; ret
        #TRUE: add eax, esp; ret
        #FALSE: add esp, eax; ret      
        code = '\x01\xd8\xc3'
        self.assert_contain_this_type(code, AddGadget)
        code = '\x01\xe0\xc3'
        self.assert_contain_this_type(code, AddGadget)
        code = '\x01\xc4\xc3'
        self.assert_not_contain_this_type(code, AddGadget)

        #8. ArithmeticConstG: designed for increasing counter
        #TRUE: add eax, 0x20; ret
        #TRUE: add eax, 0x20; ret
        #TRUE: Add esp, 0x4; ret
        #FALSE: ret      
        code = '\x83\xc0 \xc3'
        self.assert_contain_this_type(code, AddConstGadget)
        code = '\x83\xc0 \xc3'
        self.assert_contain_this_type(code, AddConstGadget)
        code = '\x83\xc4\x04\xc3'
        self.assert_contain_this_type(code, AddConstGadget)
        code = '\xc3'
        self.assert_not_contain_this_type(code, AddConstGadget)

        #8. ArithmeticLoadG: OutReg *= M[AddrReg+Offset]: designed for conducting arithmetic operations that save results in registers.
        #TRUE: add eax, [ebx + 0x40]; ret
        #TRUE: add eax, [esp + 0x40]; ret
        #FALSE: add esp, [ebx + 0x40]; ret      
        code = '\x03\x43\x40\xc3'
        self.assert_contain_this_type(code, LoadAddGadget)
        code = '\x03\x44\x24\x40\xc3'
        self.assert_contain_this_type(code, LoadAddGadget)
        code = '\x03\x63\x40\xc3'
        self.assert_not_contain_this_type(code, LoadAddGadget)
        #TRUE: sub eax, [ebx + 0x40]; ret
        code = '\x2b\x43\x40\xc3'
        self.assert_contain_this_type(code, LoadSubGadget)
        #TRUE: and eax, [ebx + 0x40]; ret
        code = '\x23\x43\x40\xc3'
        self.assert_contain_this_type(code, LoadAndGadget)
        #TRUE: xor eax, [ebx + 0x40]; ret
        code = '\x33\x43\x40\xc3'
        self.assert_contain_this_type(code, LoadXorGadget)
        

        #9. ArithmeticStoreG: M[AddrReg+Offset] *= OutReg: designed for conducting arithmetic operations that save results in memory.
        #TRUE: add [ebx + 0x40], eax; ret
        #TRUE: add [ebx + 0x40], esp; ret
        #FALSE: add [esp + 0x40], eax; ret      
        code = '\x01\x43\x40\xc3'
        self.assert_contain_this_type(code, StoreAddGadget)
        code = '\x01\x43\x40\xc3'
        self.assert_contain_this_type(code, StoreAddGadget)
        code = '\x01\x44\x24\x40\xc3'
        self.assert_not_contain_this_type(code, StoreAddGadget)
        #TRUE: sub [ebx + 0x40], eax; ret
        code = '\x29\x43\x40\xc3'
        self.assert_contain_this_type(code, StoreSubGadget)
        #TRUE: and [ebx + 0x40], eax; ret
        code = '\x21\x43\x40\xc3'
        self.assert_contain_this_type(code, StoreAndGadget)
        #TRUE: xor [ebx + 0x40], eax; ret
        code = '\x31\x43\x40\xc3'
        self.assert_contain_this_type(code, StoreXorGadget)
        #TRUE: add dword ptr [ebx + 0x40], 1; ret
        code = '\x83\x43\x40\x01\xc3'
        self.assert_contain_this_type(code, StoreAddConstGadget)
        #TRUE: sub dword ptr [ebx + 0x40], 1; ret
        code = '\x83\x6b\x40\x01\xc3'
        self.assert_contain_this_type(code, StoreSubConstGadget)       
        
        
        #10. RegJumpModifyPayload: IP = AddrReg + Offset: designed for invoking Funcall gadgets.
        #TRUE: push ebx; ret
        #FALSE: pop eax; pop ecx; push ebx; ret
        #FALSE: jmp eax
        code = '\x53\xc3'
        self.assert_contain_this_type(code, RegJumpModifyPayload)
        code = '\x58\x59\x53\xc3'
        self.assert_not_contain_this_type(code, RegJumpModifyPayload)
        code = '\xff\xe0'
        self.assert_not_contain_this_type(code, RegJumpModifyPayload)
        
        #10. MemJumpNormalG: IP = [AddrReg + Offset]: designed for finding more jump gadgets.
        #TRUE: jmp [eax]
        #TRUE: pop ebx; call [eax]
        #FALSE: call [eax]
        #FALSE: ret
        code = '\xff\x20 '
        self.assert_contain_this_type(code, MemJumpNormal)
        code = '\x5b\xff\x10'
        self.assert_contain_this_type(code, MemJumpNormal)
        code = '\xff\x10'
        self.assert_not_contain_this_type(code, MemJumpNormal)
        code = '\xc3'
        self.assert_not_contain_this_type(code, MemJumpNormal)
        
        #11. RegFuncallG: EIP = AddrReg + Offset: designed for finding more jump gadgets.
        #TRUE: call eax
        #FALSE: jmp eax
        #FALSE: pop ebx; call eax
        code = '\xff\xd0'
        self.assert_contain_this_type(code, RegJumpModifyPayload)
        code = '\xff\xe0'
        self.assert_not_contain_this_type(code, RegJumpModifyPayload)
        code = '\x5b\xff\xd0'
        self.assert_not_contain_this_type(code, RegJumpModifyPayload)

        #12. MemFuncallG: EIP = [AddrReg + Offset]: designed for finding more jump gadgets.
        #TRUE: call [eax]
        #FALSE: jmp [eax]
        #FALSE: pop ebx; call [eax]
        #FALSE: ret
        #FALSE: pop ebx; pop eax; ret
        code = '\xff\x10'
        self.assert_contain_this_type(code, MemJumpModifyPayload)
        code = '\xff\x20 '
        self.assert_not_contain_this_type(code, MemJumpModifyPayload)
        code = '\x5b\xff\x10'
        self.assert_not_contain_this_type(code, MemJumpModifyPayload)
        code = '\xc3'
        self.assert_not_contain_this_type(code, MemJumpModifyPayload)
        code = '\x5b\x58\xc3'
        self.assert_not_contain_this_type(code, MemJumpModifyPayload)

        #13. RegStackSwitchG: ESP = InReg + offset: designed for constructing loop code
        #TRUE: mov esp, eax; ret
        #TRUE: xchg eax, esp; ret
        #TRUE: leave; ret 
        #FALSE: add esp, 4; ret
        #FALSE: pop esp; ret
        #FALSE: ret
        #FALSE: mov esp, eax; jmp ebx
        code = '\x89\xc4\xc3'
        self.assert_contain_this_type(code, RegStackSwitch)
        code = '\x94\xc3'
        self.assert_contain_this_type(code, RegStackSwitch)
        code = '\xc9\xc3'
        self.assert_contain_this_type(code, RegStackSwitch) 
        code = '\x83\xc4\x04\xc3'
        self.assert_not_contain_this_type(code, RegStackSwitch)
        code = '\x5c\xc3'
        self.assert_not_contain_this_type(code, RegStackSwitch)
        code = '\xc3'
        self.assert_not_contain_this_type(code, RegStackSwitch)
        code = '\x83\xc4\xff\xe3'
        self.assert_not_contain_this_type(code, RegStackSwitch)
        
        #14. MemStackSwitchG: ESP = [InReg + offset]: designed for constructing loop code
        #TRUE: mov esp, [eax + 0x20]; ret
        #TRUE: mov esp, [esp + 0x20]; ret
        #TRUE: pop esp; ret
        #FALSE: pop esp; jump eax
        code = '\x8b\x60\x20\xc3'
        self.assert_contain_this_type(code, MemStackSwitch)
        code = '\x8b\x64\x24\x20\xc3'   #can hardly be reused
        self.assert_contain_this_type(code, MemStackSwitch) 
        code = '\x5c\xc3'
        self.assert_contain_this_type(code, MemStackSwitch)
        code = '\x5c\xff\xe0'
        self.assert_not_contain_this_type(code, MemStackSwitch)

    def run_test(self, arch, tests):
        for (expected_types, code) in tests:
            address = 0x40000
            gadget_classifier = classifier.GadgetClassifier(arch, code, address, log_level = logging.DEBUG)
            classic_gadgets = []
            if len(code) >= arch.instruction_alignment:
                classic_gadgets += gadget_classifier.create_gadgets_from_instructions(address)
            jcc_gadgets = gadget_classifier.harvest_jcc_gadgets(classic_gadgets)

            # For each returned gadget, count the number of each gadget types
            types = {}
            for g in classic_gadgets + jcc_gadgets:
                if g.address != address: #Matching the starting address of current gadget againt #address#
                    continue
                n = types.get(type(g), 0)
                types[type(g)] = n+1

            #self.assertEqual(types, expected_types)
            self.assertEqual(expected_types, types)
                                        
    def test_x86(self):
        tests = [
            ({RegStackSwitch:1}, '\x94\xc3'),   #xchg eax, esp ; ret  
            ({NOP:1}, '\xc3'),                  #ret
            ({RegJumpModifyPayload : 1}, '\xff\xd0'),   #call   *%eax
            ({RegJumpNormal : 1}, '\xff\xe0'),          #jmp  *%eax
            ({MemJumpModifyPayload : 1}, '\xff\x16'),   #call   *(%esi)
            ({MemJumpModifyPayload : 1}, '\xff\x52\x04'),      #call   *0x4(%edx)
            ({RegStackSwitch:1}, '\xc9\xc3'),   #leave; ret          
            ({RegStackSwitch:1}, '\x94\xc3'),   #xchg eax, esp ; ret
            ({}, '\x89\xcc\xff\xe2'),   #mov %ecx,%esp; jmp  *%edx
            ({}, '\x94\xfe'),           #xchg eax, esp; bad
            # dec edx; mov eax, edx; ret
            ({AddConstGadget : 1}, '\x4a\x89\xd0\xc3'), 
            #add eax, 0x24; ret
            ({AddConstGadget : 1}, '\x83\xc0\x24\xc3'),
            #add esp, 0x24; ret
            ({AddConstGadget : 1}, '\x83\xc4\x24\xc3'),
            #add esp, 8 ; pop ebx ; ret
            ({LoadMem:1}, '\x83\xc4\x08\x5b\xc3'),
            #add esp, 4 ; ret
            ({AddConstGadget : 1}, '\x83\xc4\x04\xc3'),
            #push %ebp;mov %esp,%ebp;sub $0x18,%esp;movl $0x804a03c,(%esp);call *%eax
            ({RegJumpModifyPayload : 1}, '\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x3c\xa0\x04\x08\xff\xd0'),
            #longjmp: mov %esp, %ecx; jmp *%edx
            ({RegJumpNormal:1}, '\x89\xe1\xff\xe2'),
            #sub %eax, %ecx ; ret
            ({SubGadget:1}, '\x29\xc1\xc3'),
            #sub %eax, %edx ; ret
            ({SubGadget:1}, '\x29\xc2\xc3'),
            #add %eax, %ecx ; ret
            ({AddGadget:1}, '\x01\xc1\xc3'),
            #add %eax, %edx ; ret
            ({AddGadget:1}, '\x01\xc2\xc3'),
            #pushl  0x804a004; jmp  *0x804a008
            ({}, '\xff\x35\x04\xa0\x04\x08\xff\x25\x08\xa0\x04\x08'),
            #add %esi, (%ecx); ret
            ({StoreAndGadget:1}, '\x21\x31\xc3'),
            #add (%eax), %ecx; ret
            ({LoadAddGadget:1}, '\x03\x08\xc3'),
        ]
        self.run_test(archinfo.ArchX86(), tests)

    def test_amd64(self):
        tests = [
            ({RegJumpNormal: 1},  '\xff\xe0'),                                              # jmp rax
            ({MoveReg : 2},       '\x48\x93\xc3'),                                          # xchg rbx, rax; ret
            ({MoveReg : 1},       '\x48\x89\xcb\xc3'),                                      # mov rbx,rcx; ret
            ({LoadConst : 1},     '\x48\xc7\xc3\x00\x01\x00\x00\xc3'),                      # mov rbx,0x100; ret. We prefer small constant
            ({},                  '\x48\xbb\xff\xee\xdd\xcc\xbb\xaa\x99\x88\xc3'),          # movabs rbx,0x8899aabbccddeeff; ret.
            ({AddGadget : 1},     '\x48\x01\xc3\xc3'),                                      # add rbx, rax; ret
            ({LoadMem : 1},       '\x5f\xc3'),                                              # pop rdi; ret
            ({LoadMem : 1},       '\x48\x8b\x43\x08\xc3'),                                  # mov rax,QWORD PTR [rbx+0x8]; ret
            ({LoadMem : 1},       '\x48\x8b\x07\xc3'),                                      # mov rax,QWORD PTR [rdi]; ret
            ({StoreMem : 1},      '\x48\x89\x03\xc3'),                                      # mov QWORD PTR [rbx],rax; ret
            ({StoreMem : 1},      '\x48\x89\x43\x08\xc3'),                                  # mov QWORD PTR [rbx+0x8],rax; ret
            ({StoreMem : 1},      '\x48\x89\x44\x24\x08\xc3'),                              # mov QWORD PTR [rsp+0x8],rax; ret
            ({LoadAddGadget: 1},  '\x48\x03\x03\xc3'),                                      # add rax,QWORD PTR [rbx]; ret
            ({StoreAddGadget: 1},   '\x48\x01\x43\xf8\xc3'),                                  # add QWORD PTR [rbx-0x8],rax; ret
            ({},                  '\x48\x39\xeb\xc3'),                                      # cmp rbx, rbp; ret
            ({},                  '\x5e'),                                                  # pop rsi
            ({},                  '\x8b\x04\xc5\xc0\x32\x45\x00\xc3'),                      # mov rax,QWORD PTR [rax*8+0x4532c0]
            ({LoadMem : 1, LoadConst : 1}, '\x59\x48\x89\xcb\x48\xc7\xc1\x05\x00\x00\x00\xc3'),     # pop rcx; mov rbx,rcx; mov rcx,0x5; ret
            ({},                  '\x48\x8b\x85\xf0\xfd\xff\xff\x48\x83\xc0'),
            ({RegJumpNormal : 1, },   '\x5a\xfc\xff\xd0'),                                          # pop rdx, cld, call rax
            ({LoadMem : 3, LoadMultiple : 1}, '\x5f\x5e\x5a\xc3'),                                  # pop rdi; pop rsi; pop rdx; ret
            ({AddConstGadget : 1},  '\x48\x05\x44\x33\x22\x11\xc3'),                          # add rax, 0x11223344; ret
            ({AddConstGadget : 1},                                                            # movabs rbx,0x1122334455667788; ret
            '\x48\xbb\x88\x77\x66\x55\x44\x33\x22\x11\x48\x01\xd8\xc3'),                      # add rax,rbx; ret
            ({AddConstGadget : 1}, '\x48\xff\xc0\xc3'),                                       # inc rax; ret
            ({LoadMemJump: 1, RegJumpNormal:1}, '\x5d\xff\xe0'),           #pop %rbp; jmpq *%rax;
            ({LoadMem : 2}, '\x58\x48\x89\xc3\xc3'),                                          # pop rax; mov rbx, rax; ret
            ({LoadMem : 3, LoadMultiple : 2}, '\x59\x58\x48\x89\xc3\xc3'),                    # pop rcx; pop rax; mov rbx, rax; ret
            # Don't allow more than one read from any register but the stack
            ({} , '\x48\x8b\x19\x48\x8b\x41\x08\xc3'), # mov rbx,QWORD PTR [rcx]; mov rax,QWORD PTR [rcx+0x8]; ret
        ]
        self.run_test(archinfo.ArchAMD64(), tests)

    def not_test_arm(self):
        tests = [
            ({LoadMem   : 1}, '\x08\x80\xbd\xe8'),               # pop {r3, pc}
            ({MoveReg   : 1}, '\x02\x00\xa0\xe1\x04\xf0\x9d\xe4'), # mov r0, r2; pop {pc}
            ({LoadMem   : 7, LoadMultiple : 1}, '\xf0\x87\xbd\xe8'), # pop {r4, r5, r6, r7, r8, r9, sl, pc}
            ({LoadMem   : 3, LoadMultiple : 1}, '\x04\xe0\x9d\xe5\x08\xd0\x8d\xe2'     # ldr lr, [sp, #4]; add sp, sp, #8
             + '\x0c\x00\xbd\xe8\x1e\xff\x2f\xe1'), # pop {r2, r3}; bx lr
            ({LoadMemJump : 6, RegJumpNormal : 1},
             '\x1f\x40\xbd\xe8\x1c\xff\x2f\xe1'), # pop {r0, r1, r2, r3, r4, lr}; bx r12
            ({LoadMemJump : 1, RegJumpNormal : 1},
             '\x04\xe0\x9d\xe4\x13\xff\x2f\xe1'), # pop {lr}; bx r3
            
        ]
        #self.run_test(archinfo.ArchARM(), tests[2::1])
        arch = archinfo.ArchARM()
        self.run_test(arch, tests)

    def not_test_arm_jcc(self):
        tests = [
            ({RegJumpNormal: 2, JCC:1}, '\x00\x00S\xe3\x00\x00\x00\n\x13\xff/\xe1\x1e\xff/\xe1'),
            ({RegJumpNormal : 1}, '\x13\xff\x2f\xe1'), # bx r3
            #({RegJumpNormal:2, JCC:1}, '\x03\xb1\x18\x47\x70\x47'),  #cbz r3, 10394 <register_tm_clones+0x28>; bx r3; bx lr
        ]
        #self.run_test(archinfo.ArchARM(), tests[2::1])
        arch = archinfo.ArchARM()
        self.run_jcc_test(arch, tests)
        
    def not_test_mips(self):
        tests = [
            ({LoadMem : 1},
             '\x8f\xbf\x00\x10' + # lw ra,16(sp)
             '\x8f\xb0\x00\x08' + # lw s0,8(sp)
             '\x03\xe0\x00\x08' + # jr ra
             '\x27\xbd\x00\x20' + # addiu sp,sp,32
             '\x00\x00\x00\x00'), # nop
            ({LoadMem : 6, LoadMultiple : 1},
             '\x8f\xbf\x00\x44' + # lw ra,68(sp)
             '\x8f\xb5\x00\x3c' + # lw s5,60(sp)
             '\x8f\xb4\x00\x38' + # lw s4,56(sp)
             '\x8f\xb3\x00\x34' + # lw s3,52(sp)
             '\x8f\xb2\x00\x30' + # lw s2,48(sp)
             '\x8f\xb1\x00\x2c' + # lw s1,44(sp)
             '\x8f\xb0\x00\x28' + # lw s0,40(sp)
             '\x27\xbd\x00\x48' + # addiu sp,sp,72
             '\x03\xe0\x00\x08' + # jr ra
             '\x00\x00\x00\x00'),  # nop
            ({LoadMem : 1},
             '\x8f\xb9\x00\x08' + # lw t9,8(sp)
             '\x8f\xbf\x00\x04' + # lw ra,4(sp)
             '\x03\x20\x00\x08' + # jr t9
             '\x27\xbd\x00\x10' + # addiu sp,sp,16
             '\x00\x20\x08\x25' + # move at, at (nop)
             '\x00\x20\x08\x25' + # move at, at (nop)
             '\x00\x20\x08\x25' + # move at, at (nop)
             '\x00\x20\x08\x25' + # move at, at (nop)
             '\x00\x20\x08\x25'), # move at, at (nop)
        ]
        #self.run_test(archinfo.ArchMIPS32('Iend_BE'), tests)

    def not_test_ppc_le(self):
        tests = [
            ({LoadMem : 1},
             '\x08\x00\xe1\x83' + # lwz r31,8(r1)
             '\x04\x00\x01\x80' + # lwz r0,4(r1)
             '\xa6\x03\x08\x7c' + # mtlr r0
             '\x10\x00\x21\x38' + # addi r1,r1,16
             '\x20\x00\x80\x4e'), # blr
        ]
        #self.run_test(archinfo.ArchPPC32(), tests)

    def not_test_ppc_be(self):
        tests = [
            ({LoadMem: 2, LoadMultiple : 1},
             '\x80\x01\x00\x1c' + # lwz r0,28(r1)
             '\x80\x61\x00\x08' + # lwz r3,8(r1)
             '\x80\x81\x00\x0c' + # lwz r4,12(r1)
             '\x38\x21\x00\x20' + # addi r1,r1,32
             '\x7c\x08\x03\xa6' + # mtlr r0
             '\x4e\x80\x00\x20'), # blr
        ]
        #self.run_test(archinfo.ArchPPC32('Iend_BE'), tests)

    def run_jcc_test(self, arch, tests):
        for (expected_types, code) in tests:
            address = 0x40000
            gadget_classifier = classifier.GadgetClassifier(arch, code, address, log_level = logging.DEBUG)
            classic_gadgets = []
            for i in range(0, len(code), arch.instruction_alignment): #{
                address = 0x40000 + i
                classic_gadgets += gadget_classifier.create_gadgets_from_instructions(address)
            #}end for

            jcc_gadgets = gadget_classifier.harvest_jcc_gadgets(classic_gadgets)

            # For each returned gadget, count the number of each gadget types
            types = {}
            for g in classic_gadgets + jcc_gadgets:
                n = types.get(type(g), 0)
                types[type(g)] = n+1

            #self.assertEqual(types, expected_types)
            self.assertEqual(expected_types, types)
    
    def test_x86_jcc_design(self):
        tests = [
             #jz $+3; ret; ret
             ({NOP:2, AddGadget:1}, '\x74\x01\xc3\xc3'),
             #jz $+4; jmp eax; ret
             ({NOP:1, RegJumpNormal:1, JCC:1}, '\x74\x02\xff\xe0\xc3'),
             #jz $+2; jmp eax; jmp ebx
             ({RegJumpNormal:2, JCC:1}, '\x74\x02\xff\xe0\xff\xe3'),
             #jz $+4; jmp eax; jz $+10; ret
             ({NOP:1, RegJumpNormal:1, JCC:1}, '\x74\x02\xff\xe0\x74\x10\xc3'),
             #jz $+5; jz $+10; ret; jmp eax
             ({NOP:1, RegJumpNormal:1, JCC:1}, '\x74\x03\x74\x10\xc3\xff\xe0'),
             #jz $+5; jz $+10; ret; jz $+20; jmp eax; ret
             ({NOP:2, RegJumpNormal:1, JCC:1}, '\x74\x03\x74\x10\xc3\x74\x20\xff\xe0\xc3'),
        ]
        self.run_jcc_test(archinfo.ArchX86(), tests)
        
    def test_x86_jcc(self):
        tests = [
            #call *(%esi);jb 1499f0;ret
            ({MemJumpModifyPayload : 1, NOP:1, JCC:1}, '\xff\x16\x72\xfc\xc3'),
            #ret ;mov $0x0,%eax;test %eax,%eax;je 80484bf <deregister_tm_clones+0xf>; 
            #push %ebp;mov %esp,%ebp;sub $0x18,%esp;movl $0x804a03c,(%esp);call *%eax
            ({NOP:1, RegJumpModifyPayload : 5, JCC:1}, '\xc3\xb8\x00\x00\x00\x00\x85\xc0\x74\xf6\x55\x89\xe5\x83\xec\x18\xc7\x04\x24\x3c\xa0\x04\x08\xff\xd0'),
            #jb 4; call *(%esi); je 8 ; xor %eax,%eax; ret
            ({MemJumpModifyPayload:1, LoadConst : 1, NOP:1, JCC:1}, '\x72\x02\xff\x16\x74\x02\x31\xc0\xc3'),
            #jb 4; call *(%esi); ret; je 8 ; xor %eax,%eax; ret
            ({MemJumpModifyPayload:1, LoadConst : 1, NOP:2, JCC:1}, '\x72\x02\xff\x16\xc3\x74\x02\x31\xc0\xc3'),
            #ja 4; call *(%esi); call *%eax; ret 
            ({MemJumpModifyPayload:1, RegJumpModifyPayload : 2, NOP:1, JCC:1}, '\x77\x02\xff\x16\xff\xd0\xc3'),
            #j 6 <local0>; add $0x4,%esp; ret; add $0x8,%esp; ret
            ({AddConstGadget:2, NOP:2, JCC:1}, '\x72\x04\x83\xc4\x04\xc3\x83\xc4\x08\xc3'),
            #mov (%esi),%eax;test %eax,%eax;je 0x401720;call *%eax;add $0x4,%esi;cmp %edi,%esi;jb 0x401718;pop %edi;pop %esi;ret 
            ({RegJumpModifyPayload:1, LoadMem:3, LoadMultiple:1, JCC:1, NOP:1}, '\x8b\x06\x85\xc0\x74\x02\xff\xd0\x83\xc6\x04\x3b\xf7\x72\xf1\x5f\x5e\xc3'),
        ]
        self.run_jcc_test(archinfo.ArchX86(), tests)

    def test_amd64_jcc(self):
        tests = [
            # pop %rbp; retq ; mov $0x0,%eax; test %rax,%rax; je 400895; pop %rbp; mov $0x6020b0,%edi; jmpq *%rax;
            ({LoadMem:1, NOP:1, LoadMemJump:1, RegJumpNormal:3, JCC:1} ,'\x5d\xc3\xb8\x00\x00\x00\x00\x48\x85\xc0\x74\xf4\x5d\xbf\xb0\x20\x60\x00\xff\xe0'),
            #pop %rbp; retq; je 0; jmpq *%rax
            ({LoadMem:1, NOP:1, RegJumpNormal:2, JCC:1} , '\x5d\xc3\x74\xfc\xff\xe0'),
        ]
        self.run_jcc_test(archinfo.ArchAMD64(), tests)
        
if __name__ == '__main__':
    unittest.main()
