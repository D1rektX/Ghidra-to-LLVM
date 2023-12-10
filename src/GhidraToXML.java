//@author Tejvinder Singh Toor
//@category
//@keybinding
//@menupath
//@toolbar
//EXAMPLE: analyzeHeadless ~/github/thesis/samples thesis.gpr -process fib -postScript Pcode2LLVM.java -scriptlog ~/Desktop/GhidraProjects/script.log


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

    private String getOSDefaultPath() {
        String os = System.getProperty("os.name");
    	if (os != null) {
            os = os.toLowerCase();

            if (os.contains("win")) {
                return "C:\\Users\\pasca\\Documents\\Code\\Uni\\iOSBinaryAnalysisLab\\lifter\\ghidra\\GhidraScripts\\output.xml";
            } else{
                return "/tmp/output.xml";
            }
        } else {
            log("OS name is null.");
            return "/tmp/output.xml";
        }
        //return "/tmp/output.xml";
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

    /*
     * Taken from AssembleScript.java -> basic ghidra script
     * TODO: check if instead of replacing the llvm translation needs to use atomic functions
     * I.E.: ADD.LOCK -> replaced by ADD but this could have side effects ->
     * so try with ADD.LOCK and translate this to atomic add in xmltollvm.py
     */
    private Instruction replaceCallother(Instruction instruction, Assembler asm, Listing listing) throws Exception{
    	if(!instruction.toString().contains(".LOCK")) {
        	log("Cannot replace instruction:" + instruction.getMnemonicString());
        	log("At Address: " + instruction.getAddress());
    		return instruction;
    	}

    	log("----------------------------------------------------------------");
    	log("Instruction to replace: " + instruction.toString());
    	log(instruction.getMnemonicString());
    	log("Address: " + instruction.getAddress());

        log("New instruction: " + instruction.toString().replace(".LOCK", ""));

		asm.assemble(instruction.getAddress(), instruction.toString().replace(".LOCK", ""));
    	log("----------------------------------------------------------------");
		return listing.getInstructionAt(instruction.getAddress());
    }


    @Override
    protected void run() throws Exception {

        String defaultOutputPath = getOSDefaultPath();
        File outputFile = new File(defaultOutputPath);


        DocumentBuilderFactory dFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        // program element
        Element rootElement = doc.createElement("program");
        doc.appendChild(rootElement);

        Language language = currentProgram.getLanguage();
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
        Listing listing = currentProgram.getListing();
        FunctionIterator fi = listing.getFunctions(true);
        Function func = null;

        Assembler asm = Assemblers.getAssembler(currentProgram);

        Element globals = doc.createElement("globals");
        rootElement.appendChild(globals);
        Element memory = doc.createElement("memory");
        rootElement.appendChild(memory);
        ArrayList<String> registerList = new ArrayList<>();
        ArrayList<String> registerSize = new ArrayList<>();

        ArrayList<String> memoryList = new ArrayList<>();
        ArrayList<String> memorySize = new ArrayList<>();

        while (fi.hasNext()) {
            func = fi.next();

            // function element
            Element functionElement = doc.createElement("function");
            rootElement.appendChild(functionElement);
            Attr fnameAttr = doc.createAttribute("name");
            fnameAttr.setValue(func.getName());
            functionElement.setAttributeNode(fnameAttr);

            Attr fAddress = doc.createAttribute("address");
            fAddress.setValue(func.getEntryPoint().toString());
            functionElement.setAttributeNode(fAddress);


            DecompileOptions options = new DecompileOptions();

    		DecompInterface ifc = new DecompInterface();

            DecompileResults results;

            try {
            	ifc.setOptions(options);
    			if (!ifc.openProgram(this.currentProgram)) {
    				throw new DecompileException("Decompiler",
    					"Unable to initialize: " + ifc.getLastMessage());
    			}
    			ifc.setSimplificationStyle("decompile");

    			results = ifc.decompileFunction(func, 300, null);
    		} catch (Exception e) {
    			log("Error decompiling " + func.getName());
    			continue;
			}
    		finally {
    			ifc.dispose();
    		}

            HighFunction high = results.getHighFunction();
            Element foutputElement = doc.createElement("output");
            functionElement.appendChild(foutputElement);
            Attr foutputAttr = doc.createAttribute("type");
            if (!func.hasNoReturn()) {
                foutputAttr.setValue(func.getReturnType().getDisplayName());
            } else {
                foutputAttr.setValue("void");
            }
            foutputElement.setAttributeNode(foutputAttr);

            for (int x = 0; x < func.getParameterCount(); x++) {
                Element fInputElement = doc.createElement("input");
                functionElement.appendChild(fInputElement);
                Attr fInputTypeAttr = doc.createAttribute("type");
                fInputTypeAttr.setValue(func.getParameter(x).getDataType().getDisplayName());
                fInputElement.setAttributeNode(fInputTypeAttr);
                Attr fInputNameAttr = doc.createAttribute("name");
                fInputNameAttr.setValue(func.getParameter(x).getName());
                fInputElement.setAttributeNode(fInputNameAttr);
            }
            Address entry = func.getEntryPoint();
            InstructionIterator ii = listing.getInstructions(entry, true);
            int y = 0;
            Element instructions = doc.createElement("instructions");
            functionElement.appendChild(instructions);
            while (ii.hasNext()) {
                Instruction inst = ii.next();
                PcodeOp[] pcode = inst.getPcode();
                // TODO - remove CALLOTHER

                for (int i = 0; i < pcode.length; i++) {
    				if (pcode[i].getOpcode() == PcodeOp.CALLOTHER) {
    					inst = replaceCallother(inst, asm, listing);
    					// TODO - CMPXCHG - add custom pcode to xml with instruction values
    					pcode = inst.getPcode();
    					break;
    					// throw new Exception("ENDING THE SCRIPT.");
    				}
    			}

                // END TODO
                Element instructionElement = doc.createElement("instruction_" + y);
                instructions.appendChild(instructionElement);

                Element address = doc.createElement("address");
                instructionElement.appendChild(address);
                address.appendChild(doc.createTextNode(inst.getAddress().toString()));

                Element pcodes = doc.createElement("pcodes");
                instructionElement.appendChild(pcodes);
                for (int i = 0; i < pcode.length; i++) {
                    Element pcodeElement = doc.createElement("pcode_" + i);
                    pcodes.appendChild(pcodeElement);
                    Varnode vnodeOutput = pcode[i].getOutput();
                    if (vnodeOutput != null) {
                        Element pOutputElement = doc.createElement("output");
                        pcodeElement.appendChild(pOutputElement);
                        pOutputElement.appendChild(doc.createTextNode(vnodeOutput.toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(vnodeOutput.getSize()));
                        pOutputElement.setAttributeNode(size);
                        Attr outIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (vnodeOutput.isRegister()) {
                            storage = "register";
                            if (!registerList.contains(vnodeOutput.toString(language))){
                                registerList.add(vnodeOutput.toString(language));
                                registerSize.add(String.valueOf(vnodeOutput.getSize()));
                            }
                        } else if (vnodeOutput.isConstant()){
                            storage = "constant";
                        } else if (vnodeOutput.isAddress()) {
                            storage = "memory";
                            if (!memoryList.contains(vnodeOutput.toString(language))){
                                memoryList.add(vnodeOutput.toString(language));
                                memorySize.add(String.valueOf(vnodeOutput.getSize()));
                            }
                        } else if (vnodeOutput.isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        outIsRegister.setValue(storage);
                        pOutputElement.setAttributeNode(outIsRegister);

                    }
                    Element iNameElement = doc.createElement("name");
                    pcodeElement.appendChild(iNameElement);
                    iNameElement.appendChild(doc.createTextNode(pcode[i].getMnemonic()));
                    Attr inIsRegister;
                    for (int j = 0; j < pcode[i].getNumInputs(); j++) {
                        Element pInputElement = doc.createElement("input_" + j);
                        pcodeElement.appendChild(pInputElement);
                        pInputElement.appendChild(doc.createTextNode(pcode[i].getInput(j).toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(pcode[i].getInput(j).getSize()));
                        pInputElement.setAttributeNode(size);
                        inIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (pcode[i].getInput(j).isRegister()) {
                            storage = "register";
                            if (!registerList.contains(pcode[i].getInput(j).toString(language))){
                                registerList.add(pcode[i].getInput(j).toString(language));
                                registerSize.add(String.valueOf(pcode[i].getInput(j).getSize()));
                            }
                        } else if (pcode[i].getInput(j).isConstant()){
                            storage = "constant";
                        } else if (pcode[i].getInput(j).isAddress()) {
                            storage = "memory";
                            if (!memoryList.contains(pcode[i].getInput(j).toString(language))){
                                memoryList.add(pcode[i].getInput(j).toString(language));
                                memorySize.add(String.valueOf(pcode[i].getInput(j).getSize()));
                            }
                        } else if (pcode[i].getInput(j).isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        inIsRegister.setValue(storage);
                        pInputElement.setAttributeNode(inIsRegister);
                    }
                }
                y++;
            }
        }
        for (int x = 0; x < registerList.size(); x++) {
            String regName = registerList.get(x);
            Element register = doc.createElement("register");
            Attr name = doc.createAttribute("name");
            name.setValue(registerList.get(x));
            register.setAttributeNode(name);
            Attr size = doc.createAttribute("size");
            size.setValue(registerSize.get(x));
            register.setAttributeNode(size);
            Attr flags = doc.createAttribute("flags");
            flags.setValue(Integer.toString(language.getRegister(regName).getTypeFlags()));
            register.setAttributeNode(flags);
            globals.appendChild(register);
        }

        for (int x = 0; x < memoryList.size(); x++) {
            Element memory_val = doc.createElement("memory");
            Attr name = doc.createAttribute("name");
            name.setValue(memoryList.get(x));
            memory_val.setAttributeNode(name);
            Attr size = doc.createAttribute("size");
            size.setValue(memorySize.get(x));
            memory_val.setAttributeNode(size);
            memory.appendChild(memory_val);
        }
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(outputFile);
        transformer.transform(source, result);
    }
}
