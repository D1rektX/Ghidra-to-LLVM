//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class InstructionInspector extends GhidraScript {

	
    public void run() throws Exception {
    	println("Starting.");
		if (currentProgram == null) {
	    	println("Current program is null. Exiting.");
			return;
		};
		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
			set = currentProgram.getMemory().getExecuteSet();
		}
		InstructionIterator instructions = currentProgram.getListing().getInstructions(set, true);
    	//TODO Add User Code Here
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        // Get an iterator over all instructions in the program
        inspectInstructionAndPCodes(getInstructionAt(currentAddress));
        checkXMLConversion(getInstructionAt(currentAddress));
        
        /**
         while (instructions.hasNext()) {
			Instruction instruction = instructions.next();

			Address address = instruction.getAddress();
			if (instruction.getMnemonicString().contains("CPMXCHG")) {
				inspectInstructionAndPCodes(instruction);
			}
			
		}
         */
		
        
    }
    
    private void log(String msg) {
    	println(msg);
    	System.out.println(msg);
    }
    
    private void checkXMLConversion(Instruction instruction) {
    	PcodeOp[] pcode = instruction.getPcode();
    	String s = "";
    	for (int y = 0; y < pcode.length; y++) {
    		s = s + pcode[y].toString();
    	}
    	log(s);
		log("Pcode count: " + pcode.length);
    	for (int i = 0; i < pcode.length; i++) {
    		log("Pcode(" + i + "): " + pcode[i].getMnemonic());
    		log(pcode[i].toString());
    		Varnode vnodeOutput = pcode[i].getOutput();
    		if (vnodeOutput != null) {
    			log("Output: " + vnodeOutput.toString(currentProgram.getLanguage()));
    		}
    		log("Input count: " + pcode[i].getNumInputs());
    		for (int j = 0; j < pcode[i].getNumInputs(); j++) {
				log("Input(" + j + "): " + pcode[i].getInput(j).toString(currentProgram.getLanguage()));
    		}
    		log("");
    	}
    }
    
    private void inspectInstructionAndPCodes(Instruction instruction){
    	log("----------------------------------------------------------------");
    	log("Instruction: " + instruction.toString());
    	log(instruction.getMnemonicString());
    	log("Address: " + instruction.getAddress());
    	
        PcodeOp[] pcode = instruction.getPcode();
        // TODO - remove CALLOTHER
        
        for (int i = 0; i < pcode.length; i++) {
			log(pcode[i].toString());
		}
        	
		// log("Next Address: ");
		// log(instruction.next().getAddress().toString());
    	log("----------------------------------------------------------------");
    }
}
