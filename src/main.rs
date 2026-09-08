use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use std::env;
use std::fs;
use std::io;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const CODE_FLAGS: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;

const PE_SIGNATURE_SIZE: usize = 4;
const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;

// Single‑byte XOR key – used for both encryption and decryption
const XOR_KEY: u8 = 0xDE;

const NOP_EQUIV: &[&[u8]] = &[
    &[0x90],
    &[0x66, 0x90],
    &[0x48, 0x87, 0xC0],
];

const OPAQUE_PRED: &[u8] = &[
    0x31, 0xC0,               // XOR  EAX, EAX
    0x85, 0xC0,               // TEST EAX, EAX
    0x74, 0x00,               // JZ   +0
];

const ANTI_DISASM: &[&[u8]] = &[
    &[0xEB, 0x02, 0xFF, 0x15],
    &[0x75, 0x02, 0xFF, 0x25],
];

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

fn read_u16(data: &[u8], offset: usize) -> io::Result<u16> {
    let b = data
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u16 out of bounds"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> io::Result<u32> {
    let b = data
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u32 out of bounds"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> io::Result<u64> {
    let b = data
        .get(offset..offset + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u64 out of bounds"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> io::Result<()> {
    let t = data
        .get_mut(offset..offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u16 write out of bounds"))?;
    t.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> io::Result<()> {
    let t = data
        .get_mut(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u32 write out of bounds"))?;
    t.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> io::Result<()> {
    let t = data
        .get_mut(offset..offset + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "u64 write out of bounds"))?;
    t.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn section_name(s: &SectionTable) -> String {
    String::from_utf8_lossy(&s.name)
        .trim_matches('\0')
        .to_owned()
}

fn raw_content_size(s: &SectionTable) -> usize {
    if s.virtual_size == 0 {
        s.size_of_raw_data as usize
    } else {
        s.virtual_size.min(s.size_of_raw_data) as usize
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OBFUSCATION PASSES
// ═══════════════════════════════════════════════════════════════════════════

/// Safely rewrite a few instruction patterns in‑place.
/// Currently only replaces `xchg rax, rax` (3 bytes) with two NOPs.
/// No size change.
fn rewrite_instructions(data: &mut Vec<u8>, sections: &[SectionTable]) -> io::Result<()> {
    for section in sections {
        if section.characteristics & CODE_FLAGS == 0 || section.size_of_raw_data == 0 {
            continue;
        }

        let start = section.pointer_to_raw_data as usize;
        let end = (start + section.size_of_raw_data as usize).min(data.len());
        let mut pos = start;
        let mut insn_count = 0;

        while pos + 3 <= end {
            if data[pos] == 0x48 && data[pos + 1] == 0x87 && data[pos + 2] == 0xC0 {
                data[pos] = 0x90;      // NOP
                data[pos + 1] = 0x66;  // 66 90
                data[pos + 2] = 0x90;
                insn_count += 1;
                pos += 3;
                continue;
            }
            pos += 1;
        }
        println!(
            "    [~] Safely rewrote {} instruction fragments in '{}'",
            insn_count,
            section_name(section)
        );
    }
    Ok(())
}

/// XOR‑encrypt all executable sections.
fn encrypt_code_section(data: &mut Vec<u8>, sections: &[SectionTable]) {
    for s in sections {
        if s.characteristics & CODE_FLAGS == 0
            || s.pointer_to_raw_data == 0
            || s.size_of_raw_data == 0
        {
            continue;
        }

        let start = s.pointer_to_raw_data as usize;
        let end = (start + s.size_of_raw_data as usize).min(data.len());

        println!(
            "    [~] Encrypting code in '{}' ({} bytes)",
            section_name(s),
            end - start
        );

        for byte in data[start..end].iter_mut() {
            *byte ^= XOR_KEY;
        }
    }
}

/// Insert opaque predicates and NOPs into slack space after the real code.
fn add_control_flow_obfuscation(data: &mut Vec<u8>, sections: &[SectionTable]) {
    for s in sections {
        if s.characteristics & CODE_FLAGS == 0
            || s.pointer_to_raw_data == 0
            || s.size_of_raw_data == 0
        {
            continue;
        }

        let raw_start = s.pointer_to_raw_data as usize;
        let real_end = raw_start + raw_content_size(s);
        let padded_end = (raw_start + s.size_of_raw_data as usize).min(data.len());

        let slack = padded_end.saturating_sub(real_end);
        if slack < OPAQUE_PRED.len() + 4 {
            continue;
        }

        println!(
            "    [~] CFG obfuscation in '{}' ({} slack bytes)",
            section_name(s),
            slack
        );

        let mut pos = real_end;
        if pos + OPAQUE_PRED.len() <= padded_end {
            data[pos..pos + OPAQUE_PRED.len()].copy_from_slice(OPAQUE_PRED);
            pos += OPAQUE_PRED.len();
        }

        let mut ni = 0usize;
        while pos < padded_end {
            let nop = NOP_EQUIV[ni % NOP_EQUIV.len()];
            let avail = padded_end - pos;
            let n = nop.len().min(avail);
            data[pos..pos + n].copy_from_slice(&nop[..n]);
            pos += n;
            ni += 1;
        }
    }
}

/// Generate a TLS callback stub that decrypts the first code section.
fn generate_tls_callback_stub(
    code_section_rva: u32,
    code_section_size: u32,
    image_base: u64,
) -> Vec<u8> {
    let mut stub = Vec::new();

    // PUSH RBP
    stub.push(0x55);
    // MOV RBP, RSP
    stub.extend_from_slice(&[0x48, 0x89, 0xE5]);

    // MOV RAX, ImageBase
    stub.extend_from_slice(&[0x48, 0xB8]);
    stub.extend_from_slice(&image_base.to_le_bytes());

    // ADD RAX, code_section_rva
    stub.extend_from_slice(&[0x48, 0x05]);
    stub.extend_from_slice(&code_section_rva.to_le_bytes());

    // MOV RCX, code_section_size
    stub.extend_from_slice(&[0x48, 0xB9]);
    stub.extend_from_slice(&(code_section_size as u64).to_le_bytes());

    // XOR RDX, RDX
    stub.extend_from_slice(&[0x48, 0x31, 0xD2]);

    let loop_start = stub.len();
    // CMP RDX, RCX
    stub.extend_from_slice(&[0x48, 0x39, 0xCA]);

    // JGE end (placeholder)
    let jge_offset = stub.len();
    stub.push(0x7D);
    stub.push(0x00);

    // MOV R8B, [RAX + RDX]
    stub.extend_from_slice(&[0x42, 0x8A, 0x04, 0x10]);
    // XOR R8B, XOR_KEY
    stub.extend_from_slice(&[0x41, 0x80, 0xF0, XOR_KEY]);
    // MOV [RAX + RDX], R8B
    stub.extend_from_slice(&[0x42, 0x88, 0x04, 0x10]);
    // INC RDX
    stub.extend_from_slice(&[0x48, 0xFF, 0xC2]);

    // JMP loop_start
    let jmp_back = loop_start as i32 - (stub.len() as i32 + 2);
    stub.push(0xEB);
    stub.push((jmp_back & 0xFF) as u8);

    // Patch JGE offset
    let loop_end = stub.len();
    let jge_delta = loop_end as i32 - (jge_offset as i32 + 2);
    stub[jge_offset + 1] = (jge_delta & 0xFF) as u8;

    // POP RBP
    stub.push(0x5D);
    // RET
    stub.push(0xC3);

    stub
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input.exe> <output.exe>", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    let mut data = fs::read(input_path)?;
    println!("[+] Loading: {}", input_path);
    println!("[+] Input size: {} bytes\n", data.len());

    let pe = PE::parse(&data).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Invalid PE: {e}"))
    })?;

    if !pe.is_64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Only x64 PE files are supported"));
    }

    let pe_offset = read_u32(&data, 0x3C)? as usize;
    if pe_offset + PE_SIGNATURE_SIZE + FILE_HEADER_SIZE > data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid PE header offset"));
    }
    let signature = &data[pe_offset..pe_offset + 4];
    if signature != b"PE\0\0" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid PE signature"));
    }

    let file_header_offset = pe_offset + PE_SIGNATURE_SIZE;
    let optional_header_offset = file_header_offset + FILE_HEADER_SIZE;

    let number_of_sections = read_u16(&data, file_header_offset + 2)?;
    let size_of_optional_header = read_u16(&data, file_header_offset + 16)? as usize;

    let section_table_offset = optional_header_offset + size_of_optional_header;
    let new_section_header_offset =
        section_table_offset + number_of_sections as usize * SECTION_HEADER_SIZE;

    let section_alignment = read_u32(&data, optional_header_offset + 32)?;
    let file_alignment = read_u32(&data, optional_header_offset + 36)?;
    let image_base = read_u64(&data, optional_header_offset + 24)?;

    let size_of_image_offset = optional_header_offset + 56;
    let old_size_of_image = read_u32(&data, size_of_image_offset)?;

    println!("[+] Architecture: x64");
    println!("[+] PE offset: 0x{:X}", pe_offset);
    println!("[+] Sections: {}", number_of_sections);
    println!("[+] ImageBase: 0x{:X}", image_base);
    println!("[+] Section alignment: 0x{:X}", section_alignment);
    println!("[+] File alignment: 0x{:X}\n", file_alignment);

    let sections: Vec<SectionTable> = pe.sections.iter().cloned().collect();

    // Find the first executable section
    let code_section = sections
        .iter()
        .find(|s| s.characteristics & CODE_FLAGS != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No code section found"))?;

    let code_section_rva = code_section.virtual_address;
    // CRITICAL: use exactly raw data size that will be encrypted
    let code_section_size = code_section.size_of_raw_data;

    drop(pe);

    println!("=== PHASE 1: TRANSFORMATION ===\n");

    println!("[*] Instruction-Level Rewriting");
    rewrite_instructions(&mut data, &sections)?;

    println!("\n[*] Code Encryption (single‑byte XOR)");
    encrypt_code_section(&mut data, &sections);

    println!("\n[*] Control-Flow Obfuscation");
    add_control_flow_obfuscation(&mut data, &sections);

    // Optionally add anti‑disassembly to non‑code sections here (not shown for brevity)

    println!("\n=== PHASE 2: TLS SETUP ===\n");

    let tls_callback = generate_tls_callback_stub(code_section_rva, code_section_size, image_base);

    // Compute layout for new .tls section
    let mut last_raw_end = 0u32;
    let mut last_virtual_end = 0u32;
    for s in &sections {
        last_raw_end = last_raw_end.max(s.pointer_to_raw_data + s.size_of_raw_data);
        last_virtual_end = last_virtual_end.max(s.virtual_address + s.virtual_size.max(s.size_of_raw_data));
    }

    let tls_virtual_address = align_up(last_virtual_end, section_alignment);
    let tls_raw_offset = align_up(last_raw_end, file_alignment);

    // Build TLS payload layout:
    // [0..40)   IMAGE_TLS_DIRECTORY64
    // [40..56)  callback array (one pointer + null terminator)
    // [56..)    callback code
    let mut tls_payload = vec![0u8; 40]; // reserve directory

    let callback_array_offset = 40u32;
    let callback_array_va = image_base + tls_virtual_address as u64 + callback_array_offset as u64;
    let callback_code_offset = callback_array_offset + 16; // after array (1 ptr + 1 null)
    let callback_code_va = image_base + tls_virtual_address as u64 + callback_code_offset as u64;

    // Fill IMAGE_TLS_DIRECTORY64
    write_u64(&mut tls_payload, 0, 0)?;                              // StartAddressOfRawData
    write_u64(&mut tls_payload, 8, 0)?;                              // EndAddressOfRawData
    write_u64(&mut tls_payload, 16, 0)?;                             // AddressOfIndex
    write_u64(&mut tls_payload, 24, callback_array_va)?;             // AddressOfCallBacks
    write_u32(&mut tls_payload, 32, 0)?;                             // SizeOfZeroFill
    write_u32(&mut tls_payload, 36, 0)?;                             // Characteristics

    // Append callback array (one pointer + null terminator)
    tls_payload.extend_from_slice(&[0u8; 8]);                        // placeholder, filled below
    tls_payload.extend_from_slice(&[0u8; 8]);                        // null terminator

    // Fill the first callback pointer with the VA of the stub
    let callback_array_start = callback_array_offset as usize;
    write_u64(&mut tls_payload, callback_array_start, callback_code_va)?;

    // Append the stub code
    tls_payload.extend_from_slice(&tls_callback);

    let tls_virtual_size = tls_payload.len() as u32;
    let tls_raw_size = align_up(tls_virtual_size, file_alignment);
    let new_size_of_image = align_up(tls_virtual_address + tls_virtual_size, section_alignment);

    // Resize output buffer
    if data.len() < (tls_raw_offset + tls_raw_size) as usize {
        data.resize((tls_raw_offset + tls_raw_size) as usize, 0);
    }
    data[tls_raw_offset as usize..tls_raw_offset as usize + tls_payload.len()]
        .copy_from_slice(&tls_payload);

    // Fill slack in TLS section with anti‑disasm patterns
    let mut pos = tls_raw_offset as usize + tls_payload.len();
    let mut gi = 0usize;
    while pos < (tls_raw_offset + tls_raw_size) as usize {
        let gadget = ANTI_DISASM[gi % ANTI_DISASM.len()];
        let avail = (tls_raw_offset + tls_raw_size) as usize - pos;
        let n = gadget.len().min(avail);
        data[pos..pos + n].copy_from_slice(&gadget[..n]);
        pos += n;
        gi += 1;
    }

    // Add new section header
    if new_section_header_offset + SECTION_HEADER_SIZE > data.len() {
        data.resize(new_section_header_offset + SECTION_HEADER_SIZE, 0);
    }

    let tls_section_name = b".tls\0\0\0\0";
    data[new_section_header_offset..new_section_header_offset + 8].copy_from_slice(tls_section_name);

    write_u32(&mut data, new_section_header_offset + 8, tls_virtual_size)?;
    write_u32(&mut data, new_section_header_offset + 12, tls_virtual_address)?;
    write_u32(&mut data, new_section_header_offset + 16, tls_raw_size)?;
    write_u32(&mut data, new_section_header_offset + 20, tls_raw_offset)?;
    write_u32(&mut data, new_section_header_offset + 24, 0)?;  // relocations
    write_u32(&mut data, new_section_header_offset + 28, 0)?;  // line numbers
    write_u16(&mut data, new_section_header_offset + 32, 0)?;  // reloc count
    write_u16(&mut data, new_section_header_offset + 34, 0)?;  // line count
    write_u32(
        &mut data,
        new_section_header_offset + 36,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
    )?;

    // Update PE header
    write_u16(&mut data, file_header_offset + 2, number_of_sections + 1)?;
    write_u32(&mut data, size_of_image_offset, new_size_of_image)?;

    // Clear ASLR flag (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040)
    let dll_char_offset = optional_header_offset + 70;
    let mut dll_char = read_u16(&data, dll_char_offset)?;
    dll_char &= !0x0040;
    write_u16(&mut data, dll_char_offset, dll_char)?;

    // Register TLS directory (index 9)
    let tls_data_dir_offset = optional_header_offset + 96 + (9 * 8);
    write_u32(&mut data, tls_data_dir_offset, tls_virtual_address)?;
    write_u32(&mut data, tls_data_dir_offset + 4, 40)?;  // directory size

    fs::write(output_path, &data)?;

    println!("\n[+] Modified PE written to: {}", output_path);
    println!("[+] New section count: {}", number_of_sections + 1);
    println!("[+] SizeOfImage: 0x{:X} → 0x{:X}", old_size_of_image, new_size_of_image);
    println!("[+] DYNAMIC_BASE flag cleared (ASLR disabled)");

    // Quick validation
    match PE::parse(&data) {
        Ok(pe) => {
            println!("[✓] PE parsed successfully");
            println!("    Sections: {}", pe.sections.len());
            println!("    Is 64-bit: {}", pe.is_64);
        }
        Err(e) => {
            println!("[✗] PE parse failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "PE parsing failed"));
        }
    }

    Ok(())
}
