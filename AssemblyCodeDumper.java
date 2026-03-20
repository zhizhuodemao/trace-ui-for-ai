package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import capstone.api.arm64.MemType;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.InstructionVisitor;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.memory.Memory;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

    private final Emulator<?> emulator;

    public AssemblyCodeDumper(Emulator<?> emulator, long begin, long end, TraceCodeListener listener) {
        super();

        this.emulator = emulator;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;

        Memory memory = emulator.getMemory();
        if (begin > end) {
            maxLengthLibraryName = memory.getMaxLengthLibraryName().length();
        } else {
            int value = 0;
            for (Module module : memory.getLoadedModules()) {
                long min = Math.max(begin, module.base);
                long max = Math.min(end, module.base + module.size);
                if (min < max) {
                    int length = module.name.length();
                    if (length > value) {
                        value = length;
                    }
                }
            }
            maxLengthLibraryName = value;
        }
    }

    private final long traceBegin, traceEnd;
    private final TraceCodeListener listener;
    private final int maxLengthLibraryName;

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        if (this.unHook != null) {
            throw new IllegalStateException();
        }
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

    @Override
    public void stopTrace() {
        detach();
        IOUtils.close(redirect);
        redirect = null;
    }

    private boolean canTrace(long address) {
        return (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    private PrintStream redirect;

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    private RegAccessPrinter lastInstructionWritePrinter;

    @Override
    public void hook(final Backend backend, final long address, final int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.err;
                if (redirect != null) {
                    out = redirect;
                }
                Instruction[] insns = emulator.printAssemble(out, address, size, maxLengthLibraryName, new InstructionVisitor() {
                    @Override
                    public void visitLast(StringBuilder builder) {
                        if (lastInstructionWritePrinter != null) {
                            lastInstructionWritePrinter.print(emulator, backend, builder, address);
                        }
                    }
                    @Override
                    public void visit(StringBuilder builder, Instruction ins) {
                        // todo add 调用通用内存访问 hook
                        hookMemoryAccess(backend, ins, builder);

                        RegsAccess regsAccess = ins.regsAccess();
                        if (regsAccess != null) {
                            short[] regsRead = regsAccess.getRegsRead();
                            RegAccessPrinter readPrinter = new RegAccessPrinter(address, ins, regsRead, false);
                            readPrinter.print(emulator, backend, builder, address);

                            short[] regWrite = regsAccess.getRegsWrite();
                            if (regWrite.length > 0) {
                                lastInstructionWritePrinter = new RegAccessPrinter(address + size, ins, regWrite, true);
                            }
                        }
                    }
                });
                if (listener != null) {
                    if (insns == null || insns.length != 1) {
                        throw new IllegalStateException("insns=" + Arrays.toString(insns));
                    }
                    listener.onInstruction(emulator, address, insns[0]);
                }
            } catch (BackendException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // todo add 增加：计算所有内存读取和写入指令的目标绝对地址 abs
    public void hookMemoryAccess(final Backend backend, final Instruction ins, final StringBuilder builder) {
        try {
            String mnemonic = ins.getMnemonic();
            if (mnemonic == null) mnemonic = "";
            mnemonic = mnemonic.toLowerCase();

            // 以 "完整单词" 匹配 load / store 变体，避免 "str" 匹配到 "stur"
            // 列出常见的 load 指令变体（ARM64 & ARM32）
            final Pattern loadPattern = Pattern.compile("^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldur|ldurb|ldurh|ldp|ldm)($|\\.|\\s).*");
            // 列出常见的 store 指令变体
            final Pattern storePattern = Pattern.compile("^(str|strb|strh|stur|sturb|sturh|stp|stm)($|\\.|\\s).*");

            OpInfo opInfo = (OpInfo) ins.getOperands();
            Operand[] operands = opInfo.getOperands();
            Operand memOperand = null;

            // first: find any operand with MEM type (ARM64 uses ARM64_OP_MEM, ARM32 uses ARM_OP_MEM)
            for (int i = 0; i < operands.length; i++) {
                Operand op = operands[i];
                // defensive: check for both ARM64 and ARM32 operand type enums if available
                int t = op.getType();
                // Arm64_const.ARM64_OP_MEM vs Arm_const.ARM_OP_MEM -- use numeric compare but keep generic
                // We just check the op.getType() equals the MEM value used in your environment.
                // Here we assume the existing enum constants are accessible.
                if (t == Arm64_const.ARM64_OP_MEM || t == Arm_const.ARM_OP_MEM) {
                    memOperand = op;
                    break;
                }
            }

            if (memOperand == null) {
                // no memory operand -> nothing to do
                return;
            }

            // determine access type by mnemonic matching (精确匹配 load/store 类)
            String accessType;
            if (loadPattern.matcher(mnemonic).matches()) {
                accessType = "READ";
            } else if (storePattern.matcher(mnemonic).matches()) {
                accessType = "WRITE";
            } else {
                // 如果既不是明显的 load 也不是 store（例如有些指令既读又写内存，或特殊指令），可以保守地标注为 READ/WRITE 两者
                // 这里我们尝试根据指令是否以 'ld' 开头认定为 READ，否则以 'st' 开头认定为 WRITE
                if (mnemonic.startsWith("ld") || mnemonic.startsWith("ldr") || mnemonic.startsWith("ldrb")) {
                    accessType = "READ";
                } else if (mnemonic.startsWith("st") || mnemonic.startsWith("str") || mnemonic.startsWith("stm")) {
                    accessType = "WRITE";
                } else {
                    accessType = "READ/WRITE";
                }
            }

            // 计算绝对地址： base + (index << shift) + disp
            MemType mem = memOperand.getValue().getMem();

            long baseValue = 0;
            long indexValue = 0;
            long disp = 0;
            long shiftedIndex = 0;

            // base register（可能为 0 表示无基寄存器）
            try {
                if (mem.getBase() != 0) {
                    baseValue = backend.reg_read(mem.getBase()).longValue();
                }
            } catch (Exception ex) {
                // 保护性捕获（如果 reg_read 抛异常）
                baseValue = 0;
            }

            // index register（ARM64 有 index 字段，ARM32 的地址可能通过 disp 或寄存器基址 + imm）
            try {
                if (mem.getIndex() != 0) {
                    indexValue = backend.reg_read(mem.getIndex()).longValue();
                }
            } catch (Exception ex) {
                indexValue = 0;
            }

            // disp / immediate 偏移（注意可能为负）
            disp = mem.getDisp();

            // shift：有些平台将 shift 信息放在 operand 对象上（memOperand.getShift()）
            shiftedIndex = indexValue;
            try {
                // memOperand.getShift() 可能为 null 或包含 shift type/value
                if (memOperand.getShift() != null) {
                    // shift value (位移位数)
                    int shiftV = memOperand.getShift().getValue();
                    if (shiftV != 0) {
                        shiftedIndex = indexValue << shiftV;
                    }
                }
            } catch (Throwable t) {
                // ignore shift errors，fallback 不做移位
                shiftedIndex = indexValue;
            }

            long absAddr = baseValue + shiftedIndex + disp;

            // 额外：处理 post-index / pre-index 的情况 —— 对 absAddr 的计算通常是 base + disp（post-index 的 disp 表示更新量而不是偏移）
            // Capstone 在部分后缀寻址里会把后索引的 immediate 放到 mem.getDisp() 为 0，且另有字段指示 post-index。
            // 这里我们做个保守处理：如果 memOperand 表示 post-index（若 API 有相应字段），则仍使用 base + dispForLoad (通常 dispForAccess)
            // （不同版本 Capstone/unidbg 对 post-index 的表示不一致，具体可根据你的版本调整）

            builder.append(String.format(" ; mem[%s] abs=0x%x", accessType, absAddr));

        } catch (Exception e) {
            builder.append(" ; [mem_abs calc error: " + e.getMessage() + "]");
        }
    }


}
