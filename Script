# -*- coding: utf-8 -*-
# Ghidra Script per Rilevamento Automatico di Reflective PE Loaders


from __future__ import division
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp, Varnode
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType

# --- CONFIGURAZIONE TARGET ---

TARGET_APIS = {
    "CryptAcquireContext", "CryptImportKey", "CryptDestroyKey",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "CreateFile", "WriteFile", "ReadFile",
    "MoveFile", "DeleteFile", "CloseHandle", "VirtualAlloc"
}

TARGET_LOADERS = {
    "LoadLibrary", "GetModuleHandle"
}

TARGET_RESOLVERS = {
    "GetProcAddress", "LdrGetProcedureAddress"
}

MEM_APIS = {
    "VirtualAlloc", "VirtualProtect", "VirtualFree", "GlobalAlloc", "LoadLibraryA", "GetProcAddress", "FreeLibrary"
}

VALID_STARTERS = {0x55, 0xE9, 0xEB, 0xFF, 0x8B, 0x53, 0x56, 0x57}
MAGIC_MZ = 0x5a4d
MAGIC_PE = 0x4550

FLAGS_ALLOC = {
    0x40: "RWX",
    0x1000: "COMMIT",
    0x3000: "COMMIT|RESERVE"
}

MAX_STACK_CLIMB = 5

# --- HELPER FUNCTIONS ---

def get_references(api_name, symbol_table):
    all_refs = []
    # Cerca simboli che contengono il nome
    for sym in symbol_table.getAllSymbols(False):
        if api_name in sym.getName():
            addr = sym.getAddress()
            for r in getReferencesTo(addr):
                if r.getReferenceType().isCall() or r.getReferenceType().isRead():
                    all_refs.append(r)
    return all_refs

def get_function_at(addr):
    if not addr: return None
    return currentProgram.getFunctionManager().getFunctionContaining(addr)

def to_addr(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def get_data_at(addr):
    return currentProgram.getListing().getDataAt(addr)

def get_string_at_addr(addr):
    """Legge una stringa ASCII dall'indirizzo di memoria."""
    if not addr: return None
    mem = currentProgram.getMemory()
    res = ""
    try:
        for i in range(64):
            b = mem.getByte(addr.add(i))
            if b == 0: break
            if 32 <= b <= 126: res += chr(b)
            else: return None
        return res if len(res) > 3 else None
    except: return None

# --- FUNZIONI DI UTILITA' ---

def rename(name, address, symbol_table):
    if not address or address.isExternalAddress(): return
    
    # Pulizia nome
    clean_name = str(name).strip("'").strip('"')
    new_name = "PTR_" + clean_name
    
    if not currentProgram.getMemory().contains(address): return
    symbols = symbol_table.getSymbols(address)
    for symbol in symbols:
        if symbol.getName() == new_name: return
    try:
        symbol_table.createLabel(address, new_name, SourceType.USER_DEFINED)
        print("    [SUCCESS] Ridenominato: {} -> {}".format(address, new_name))
    except Exception as e:
        print("    [ERROR] Errore su {}: {}".format(address, str(e)))

def def_backtracer(vn, decomp, depth=0, max_depth=10, trace=None):
    if trace is None: trace = []
    if vn is None or depth > max_depth: return None
    
    # 1. Caso Base: Costante
    if vn.isConstant():
        return {"type": "CONST", "value": vn.getOffset(), "trace": trace}
    
    vn_def = vn.getDef()
    if vn_def:
        mnemonic = vn_def.getMnemonic()
        
        # 2. Caso COPY/CAST
        if mnemonic in ["COPY", "CAST", "INT_ZEXT", "INT_SEXT"]:
            return def_backtracer(vn_def.getInput(0), decomp, depth+1, max_depth, trace)
        
        # 3. Caso LOAD
        if mnemonic == "LOAD":
             ptr_res = def_backtracer(vn_def.getInput(1), decomp, depth+1, max_depth, trace)
             if ptr_res and ptr_res.get("type") == "CONST":
                 return {"type": "CONST", "value": ptr_res["value"], "is_memory_load": True}

        # 4. Caso PTRSUB / INT_ADD 
        if mnemonic in ["PTRSUB", "INT_ADD", "PTRADD"]:
            base_vn = vn_def.getInput(0)
            off_vn = vn_def.getInput(1)
            
            # Caso standard: Base + Offset Costante
            if off_vn.isConstant():
                offset_val = off_vn.getOffset()
                res = def_backtracer(base_vn, decomp, depth+1, max_depth, trace)
                
                if res and res.get("type") == "CONST":
                    return {"type": "CONST", "value": res["value"] + offset_val, "trace": trace}
                elif res is None and base_vn.isConstant():
                     return {"type": "CONST", "value": base_vn.getOffset() + offset_val, "trace": trace}

    return {"type": "UNKNOWN"}

def find_api_loading(func_name, func_refs, arg_index, decomp):
    call_addrs = []
    if not isinstance(func_refs, list): func_refs = [func_refs]
    
    for ref in func_refs:
        call_addr = ref.getFromAddress()
        low_func = get_function_at(call_addr)
        if not low_func: continue
        
        dec_func = decomp.decompileFunction(low_func, 30, ConsoleTaskMonitor())
        if not dec_func.decompileCompleted(): continue
        high_func = dec_func.getHighFunction()
        
        ops_iter = high_func.getPcodeOps(call_addr)
        op = None
        while ops_iter.hasNext():
            current_op = ops_iter.next()
            if current_op.getMnemonic() in ["CALL", "CALLIND"]:
                op = current_op; break
        
        if op and op.getNumInputs() > arg_index:
            # 1. Trova il nome dell'API
            param_vn = op.getInput(arg_index)
            val_param = None
            
            param_res = def_backtracer(param_vn, decomp)
            if param_res and param_res.get("type") == "CONST":
                addr_val = to_addr(param_res["value"])
                str_content = get_string_at_addr(addr_val)
                val_param = str_content if str_content else "ADDR_" + str(addr_val) 

            # 2. Trova la destinazione (STORE)
            output_vn = op.getOutput()
            dest_address = None
            
            if output_vn:
                high_var = output_vn.getHigh()
                if high_var and high_var.getSymbol() and high_var.getSymbol().getStorage().isMemoryStorage():
                    dest_address = high_var.getSymbol().getStorage().getMinAddress()
                
                if not dest_address:
                    for out_ref in output_vn.getDescendants():
                        mnemonic = out_ref.getMnemonic()
                        if mnemonic == "STORE":
                            ptr_vn = out_ref.getInput(1)
                            if ptr_vn.isConstant():
                                dest_address = to_addr(ptr_vn.getOffset())
                                break
                        elif mnemonic in ["COPY", "CAST"]:
                            sub_out = out_ref.getOutput()
                            if sub_out:
                                for sub_ref in sub_out.getDescendants():
                                    if sub_ref.getMnemonic() == "STORE":
                                        ptr_vn = sub_ref.getInput(1)
                                        if ptr_vn.isConstant():
                                            dest_address = to_addr(ptr_vn.getOffset())
                                            break
            if val_param:
                call_addrs.append({
                    "Function": func_name, "Value_param": val_param, 
                    "Call_address": call_addr, "Dest_address": dest_address, "Caller_func": low_func
                })
    return call_addrs

# --- WRAPPER SCAN ---

def analyze_wrappers(listing, sym_table, mem):
    print("--- Analisi Wrapper ---")
    found_map = {}
    for api_name in MEM_APIS:
        symbols = sym_table.getSymbols(api_name)
        for sym in symbols:
            if not sym.isExternal(): continue
            iat_refs = getReferencesTo(sym.getAddress())
            for ref in iat_refs:
                if not ref.getReferenceType().isData(): continue
                iat_addr = ref.getFromAddress()
                code_refs = getReferencesTo(iat_addr)
                for code_ref in code_refs:
                    call_addr = code_ref.getFromAddress()
                    instr = listing.getInstructionAt(call_addr)
                    if not instr or not (instr.getFlowType().isCall() or instr.getFlowType().isJump()): continue
                    
                    curr_addr = call_addr
                    for i in range(64): 
                        refs_to_curr = getReferencesTo(curr_addr)
                        ptr_source = None
                        for r in refs_to_curr:
                            if r.getReferenceType().isData() or r.getReferenceType().isRead():
                                ptr_source = r.getFromAddress()
                                break
                        if ptr_source:
                            try:
                                start_byte = mem.getByte(curr_addr) & 0xFF
                                if start_byte in VALID_STARTERS:
                                    new_name = "WRAP_" + api_name
                                    found_map[curr_addr.getOffset()] = new_name
                                    print("[SUCCESS] Wrapper: {} @ {}".format(new_name, curr_addr))
                                    sym_table.createLabel(curr_addr, new_name, SourceType.USER_DEFINED)
                            except: pass
                            break 
                        curr_addr = curr_addr.subtract(1)
    return found_map

# --- HUNTING LOGIC ---

def check_heuristic_and_trace_wrapper(func, decomp, wrappers_map, inherited_wrappers=0):
    if not func: return False
    monitor = ConsoleTaskMonitor()
    hf_res = decomp.decompileFunction(func, 15, monitor)
    if not hf_res.decompileCompleted(): return False
    
    found_mz = False
    found_pe = False
    internal_wrapper_count = 0
    
    # 1. Analisi statica interna (MZ, PE e Wrapper chiamati direttamente)
    ops = hf_res.getHighFunction().getPcodeOps()
    while ops.hasNext():
        op = ops.next()
        mnemonic = op.getMnemonic()
        
        if mnemonic in ["INT_EQUAL", "INT_NOTEQUAL"]:
            for i in range(op.getNumInputs()):
                vn = op.getInput(i)
                if vn.isConstant():
                    val = vn.getOffset()
                    if val == MAGIC_MZ: found_mz = True
                    elif val == MAGIC_PE: found_pe = True
        
        if mnemonic in ["CALL", "CALLIND"]:
            target_vn = op.getInput(0)
            target_trace = def_backtracer(target_vn, decomp, max_depth=3)
            if target_trace and target_trace.get("type") == "CONST":
                addr_val = target_trace["value"]
                if addr_val in wrappers_map:
                    internal_wrapper_count += 1

    # 2. Calcolo Punteggio Totale
    total_wrappers = internal_wrapper_count + inherited_wrappers
    
    score = 0
    evidence = []

    if found_mz:
        score += 30
        evidence.append("Found MZ")
    
    if found_pe:
        score += 40
        evidence.append("Found PE")
        
    if found_mz and found_pe:
        score += 10
        evidence.append("Structure Check")

    if total_wrappers > 0:
        w_score = min(total_wrappers * 20, 60)
        score += w_score
        evidence.append("Uses {} Wrappers (Inherited: {}, Internal: {})".format(
            total_wrappers, inherited_wrappers, internal_wrapper_count
        ))

    final_score = min(score, 100)

    if final_score >= 45:
        return {
            "score": final_score,
            "details": {
                "found_mz": found_mz,
                "found_pe": found_pe,
                "wrappers": total_wrappers,
                "reason": ", ".join(evidence)
            }
        }

    return None


def scan_function_calls(func, start_addr, decomp, wrappers_map, current_depth=0, max_depth=100, inherited_wrappers=0):
    if current_depth > max_depth or func.isExternal(): return None
    
    # 1. Verifica Euristica sulla funzione corrente
    heur_res = check_heuristic_and_trace_wrapper(func, decomp, wrappers_map, inherited_wrappers)
    
    if heur_res:
        print("  " * current_depth + "[?] Checking {}: Score {} ({})".format(
            func.getName(), heur_res["score"], heur_res["details"]["reason"]))
            
        if heur_res["score"] >= 80: 
            return func

    monitor = ConsoleTaskMonitor()
    hf_res = decomp.decompileFunction(func, 20, monitor)
    if not hf_res.decompileCompleted(): return None
    
    ops = hf_res.getHighFunction().getPcodeOps()
    while ops.hasNext():
        op = ops.next()
        
        if start_addr and current_depth == 0 and op.getSeqnum().getTarget() <= start_addr: continue
        
        if op.getMnemonic() == "CALL":
            target_addr = op.getInput(0).getAddress()
            target_func = get_function_at(target_addr)
            
            if target_func:
                # --- LOGICA PUSH ARGOMENTI ---
                passed_wrappers_count = 0
                
                for i in range(1, op.getNumInputs()):
                    arg_vn = op.getInput(i)
                    trace = def_backtracer(arg_vn, decomp, max_depth=3)
                    
                    if trace and trace.get("type") == "CONST":
                        val = trace["value"]
                        if val in wrappers_map:
                            passed_wrappers_count += 1
                
                
                should_scan = target_func.getBody().getNumAddresses() > 10 or passed_wrappers_count > 0
                
                if should_scan:
                    found = scan_function_calls(
                        target_func, 
                        None, 
                        decomp, 
                        wrappers_map, 
                        current_depth + 1, 
                        max_depth, 
                        passed_wrappers_count 
                    )
                    if found: return found
                    
    return None

def recursive_loader_hunt(current_func, start_addr, decomp, wrappers_map, visited, depth):
    if depth > MAX_STACK_CLIMB: return None
    if current_func.getEntryPoint() in visited: return None
    visited.add(current_func.getEntryPoint())
    
    print("    " * depth + "-> Scanning: {}".format(current_func.getName()))
    
    loader = scan_function_calls(current_func, start_addr if depth == 0 else None, decomp, wrappers_map, 0, 3, 0)
    
    if loader: return loader
    
    refs = getReferencesTo(current_func.getEntryPoint())
    for ref in refs:
        if ref.getReferenceType().isCall():
            parent = get_function_at(ref.getFromAddress())
            if parent:
                found = recursive_loader_hunt(parent, None, decomp, wrappers_map, visited, depth + 1)
                if found: return found
    return None

def trace_payload_bridge(decrypted_buffers, decomp, wrappers_map):
    print("\n" + "="*60)
    print("--- FASE 2: DEEP HUNTING (Ricorsione Stack) ---")
    print("="*60)
    for res in decrypted_buffers:
        caller = res.get("Caller_func")
        print("\n[*] Start Point: {} in {}".format(res["Value_param"], caller.getName()))
        visited = set()
        loader = recursive_loader_hunt(caller, res.get("Call_address"), decomp, wrappers_map, visited, 0)
        if loader:
            print("\n[SUCCESS] LOADER PE IDENTIFICATO: {}".format(loader.getName()))
            currentProgram.getBookmarkManager().setBookmark(
                loader.getEntryPoint(), "Analysis", "Reflective Loader", "Deep Trace Detection"
            )

# --- MAIN ---

def main():
    print("\n--- WannaCry Deep Analyzer v5.9 ---")
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    symbol_table = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    
    wrappers_map = analyze_wrappers(listing, symbol_table, mem)
    if not wrappers_map:
        st = currentProgram.getSymbolTable()
        gn = currentProgram.getGlobalNamespace()
        for sym in st.getSymbols(gn):
            if sym.getName().startswith("WRAP_") or sym.getName().startswith("PTR_WRAP_"):
                wrappers_map[sym.getAddress().getOffset()] = sym.getName()
    print("[*] Wrappers attivi: {}".format(len(wrappers_map)))

    # 1. ANALISI E RINOMINA (GetProcAddress)
    print("\n--- Analisi Risoluzione API ---")
    resolver_refs = get_references("GetProcAddress", symbol_table)
    if resolver_refs:
        calls = find_api_loading("GetProcAddress", resolver_refs, 2, decomp)
        for call in calls:
            found_name = str(call["Value_param"])
            dest = call["Dest_address"]
            print("[*] Risoluzione: '{}' -> Destinazione: {}".format(found_name, dest))
            
            for target in TARGET_APIS:
                if target in found_name:
                    if dest: rename(found_name, dest, symbol_table)
                    break

    # 2. RICERCA USI CRYPTDECRYPT
    CD_res = []
    targets_cd = ["CryptDecrypt", "PTR_CryptDecrypt", "PTR_CryptDecryptA"]
    CD_refs = []
    for t in targets_cd: CD_refs.extend(get_references(t, symbol_table))
    
    processed_addrs = set()
    print("\n--- Analisi CryptDecrypt Usage ---")
    
    for ref in CD_refs:
        call_addr = ref.getFromAddress()
        if call_addr in processed_addrs: continue
        caller_func = get_function_at(call_addr)
        if not caller_func: continue
        
        is_resolver = False
        
        print("    [+] Trovato uso di CryptDecrypt in: {}".format(caller_func.getName()))
        CD_res.append({"Value_param": "CryptCall", "Call_address": call_addr, "Caller_func": caller_func})
        processed_addrs.add(call_addr)
    
    # 3. AVVIO SCANSIONE
    trace_payload_bridge(CD_res, decomp, wrappers_map)
    print("\n[*] Analisi Completata.")

main()
