import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Attr;

import generic.util.Path;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.sleigh.grammar.SleighParser_SemanticParser.return_stmt_return;

import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;


public class GhidraToXML extends HeadlessScript {

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

        for (int i = 0; i < pcode.length; i++) {
			log(pcode[i].getMnemonic());
		}

		// log("Next Address: ");
		// log(instruction.next().getAddress().toString());
    	log("----------------------------------------------------------------");
    }

    @Override
    protected void run() throws Exception {
        Language language = currentProgram.getLanguage();
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
        Listing listing = currentProgram.getListing();
        FunctionIterator fi = listing.getFunctions(true);

        if (currentProgram == null) {
			return;
		}
		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
			set = currentProgram.getMemory().getExecuteSet();
		}

		Disassembler.clearUnimplementedPcodeWarnings(currentProgram, set, monitor);

		int completed = 0;
		monitor.initialize(set.getNumAddresses());

		InstructionIterator instructions = currentProgram.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instructions.next();

			// Inspect instructions
            inspectInstructionAndPCodes(instr);

			completed += instr.getLength();
			if ((completed % 1000) == 0) {
				monitor.setProgress(completed);
			}
		}
    }