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

public class FindWarnings extends GhidraScript {

	
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
        
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();

			Address address = instruction.getAddress();


            // Check if there is a warning bookmark at the instruction's address
            Bookmark[] bookmarks = bookmarkManager.getBookmarks(address);
            for (Bookmark bookmark : bookmarks) {
                if (bookmark.getTypeString().equals("Warning")) {
                	if(bookmark.toString().contains("CallOther PcodeOp"))
                	{
                		// check if operation iss add/sub lock -> replace with add / sub
                		println("Instruction with Warning Bookmark: " + address.toString() + " - " + instruction.toString());
                		
                		println(instruction.getMnemonicString());
                		// inspectInstructionAndPCodes(instruction);
                		
                	}
                }
            }
			
			
		}
		
        
    }
    private void log(String msg) {
    	println(msg);
    	System.out.println(msg);
    }
    private void inspectInstructionAndPCodes(Instruction instruction){
    	log("----------------------------------------------------------------");
    	log("Instruction: " + instruction.toString());
    	log(instruction.getMnemonicString());
    	log("Address: " + instruction.getAddress());
    	
        PcodeOp[] pcode = instruction.getPcode();
        // TODO - remove CALLOTHER
        
        for (int i = 0; i < pcode.length; i++) {
			log(pcode[i].getMnemonic());
		}
        	
		// log("Next Address: ");
		// log(instruction.next().getAddress().toString());
    	log("----------------------------------------------------------------");
    }
}
