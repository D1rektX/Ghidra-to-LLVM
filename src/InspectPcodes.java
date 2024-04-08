import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;


public class InspectPcodes extends GhidraScript {

	private void log(String msg) {
		println(msg);
		System.out.println(msg);
	}

	private void inspectInstructionAndPCodes(Instruction instruction, Assembler asm){
		log("----------------------------------------------------------------");
		log("Instruction: " + instruction.toString());
		log("Address: " + instruction.getAddress());

		PcodeOp[] pcode = instruction.getPcode();

		for (int i = 0; i < pcode.length; i++) {
			log(pcode[i].getMnemonic());
			log(pcode[i].toString());
		}
		
		log("----------------------------------------------------------------");

		if(instruction.toString().contains("brk")) {
			log("Removing brk instruction...");
			patchBRK(instruction, asm);
		}

	}

	@Override
	protected void run() throws Exception {
		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
			set = currentProgram.getMemory().getExecuteSet();
		}

		Disassembler.clearUnimplementedPcodeWarnings(currentProgram, set, monitor);

		int completed = 0;
		monitor.initialize(set.getNumAddresses());

		Assembler asm = Assemblers.getAssembler(currentProgram);

		InstructionIterator instructions = currentProgram.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instructions.next();

			// Inspect instructions
			inspectInstructionAndPCodes(instr, asm);

			completed += instr.getLength();
			if ((completed % 1000) == 0) {
				monitor.setProgress(completed);
			}
		}
	}
}