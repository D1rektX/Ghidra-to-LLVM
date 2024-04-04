import llvmlite.binding as llvm


def optimize(module, level):
    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    module_ref = llvm.parse_assembly(str(module))

    module_ref.triple = llvm.targets.get_default_triple()

    if level is None:
        return module_ref
    pmb = llvm.create_pass_manager_builder()
    pm = llvm.create_module_pass_manager()
    pmb.opt_level = level
    pmb.populate(pm)
    pm.run(module_ref)
    return module_ref

def create_execution_engine():
    """
    Create an ExecutionEngine suitable for JIT code generation on
    the host CPU.  The engine is reusable for an arbitrary number of
    modules.
    """
    # Create a target machine representing the host
    target = llvm.Target.from_default_triple()
    target_machine = target.create_target_machine()
    # And an execution engine with an empty backing module
    backing_mod = llvm.parse_assembly("")
    engine = llvm.create_mcjit_compiler(backing_mod, target_machine)
    return engine

def verify(module):
    engine = create_execution_engine()
    engine.add_module(module)
    engine.finalize_object()
    engine.run_static_constructors()

    module_bc = llvm.parse_bitcode(module.as_bitcode())
    module_bc.verify()

    return module_bc


def graph(module, base_directory):
    module_ref = llvm.parse_assembly(str(module))
    functions = module_ref.functions
    images = []
    for func in functions:
        cfg = llvm.get_function_cfg(func)
        graph = llvm.view_dot_graph(cfg, view=False)
        image = graph.render(format='png', directory=base_directory + "graphs")
        images.append(image)
    return images