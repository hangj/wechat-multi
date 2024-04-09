use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction, IntelFormatter, Register,
};
use mach_object::{
    FatArch, FatHeader, MachHeader, CPU_ARCH_ABI64, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_X86_64,
    FAT_MAGIC, LC_MAIN, MH_CIGAM, MH_CIGAM_64, MH_EXECUTE, MH_MAGIC, MH_MAGIC_64,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        return Err(anyhow::anyhow!("Usage: {} path/to/file", args[0]));
    }

    let mut f = File::open(&args[1])?;
    let fat = parse_fat_header(&mut f)?;
    println!("fat_header: {:#?}", fat);

    let arch = fat
        .archs
        .iter()
        .find(|arch| arch.cputype == CPU_TYPE_X86_64 && arch.cpusubtype == CPU_SUBTYPE_X86_64_ALL)
        .expect("Can't find x86_64 architecture");

    f.seek(std::io::SeekFrom::Start(arch.offset))?;

    let mach_header = parse_mach_header(&mut f)?;
    println!("mach_header: {:#?}", mach_header);

    assert_eq!(mach_header.filetype, MH_EXECUTE);

    let mut entryoff = 0;

    let mut bytes = [0u8; 4];
    for _ in 0..mach_header.ncmds {
        f.read_exact(&mut bytes)?;
        let cmd = u32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        let cmdsize = u32::from_le_bytes(bytes);
        if cmd != LC_MAIN {
            f.seek(std::io::SeekFrom::Current(cmdsize as i64 - 8))?;
        } else {
            let mut bytes = [0u8; 8];
            f.read_exact(&mut bytes)?;
            entryoff = u64::from_le_bytes(bytes);
            break;
        }
    }

    f.seek(std::io::SeekFrom::Start(arch.offset + entryoff))?;

    let mut text = [0u8; 1024];
    f.read_exact(&mut text)?;
    // println!("{:02x?}", text);

    let mut encoder = Encoder::new(64);

    let mut decoder = Decoder::new(64, &text, DecoderOptions::NONE);
    let mut instruction = Instruction::new();

    let mut formatter = IntelFormatter::new();
    let mut output = String::new();

    // cmp    QWORD PTR [rbp-0x30],0x2
    // jb     0x2d4
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }

        if instruction.code() == Code::Cmp_rm64_imm8
            && instruction.memory_base() == Register::RBP
            && instruction.memory_displ_size() == 1
        {
            let imm = instruction.immediate8();
            let imm2 = instruction.immediate8_2nd();
            println!("imm: {:02x?}", imm); // 0x2
            println!("imm2: {:02x?}", imm2); // 0xd0

            encoder.encode(&instruction, 0)?;
            let opcode = encoder.take_buffer();
            println!("opcode: {:02x?}", opcode);

            output.clear();
            formatter.format(&instruction, &mut output);
            println!("{}", output);

            let ip = decoder.ip();
            // println!("ip: {:#04x}", ip);

            if decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                if instruction.is_invalid() {
                    break;
                }
                encoder.encode(&instruction, ip)?;
                let opcode = encoder.take_buffer();
                println!("opcode: {:02x?}", opcode);
                output.clear();
                formatter.format(&instruction, &mut output);
                println!("{}", output);

                if instruction.code() == Code::Jb_rel32_64 {
                    instruction.set_code(Code::Jmp_rel32_64);
                    encoder.encode(&instruction, ip)?;
                    let opcode = encoder.take_buffer();
                    println!("new opcode: {:02x?}", opcode);

                    output.clear();
                    formatter.format(&instruction, &mut output);
                    println!("{}", output);

                    let mut f = OpenOptions::new().write(true).open(&args[1])?;
                    f.seek(std::io::SeekFrom::Start(arch.offset + entryoff + ip))?;
                    f.write(&opcode)?;
                    f.flush()?;

                    break;
                }
            }
        }
    }

    Ok(())
}

fn parse_fat_header(f: &mut File) -> anyhow::Result<FatHeader> {
    // https://opensource.apple.com/source/xnu/xnu-123.5/EXTERNAL_HEADERS/mach-o/fat.h.auto.html
    // big-endian order

    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    let magic = u32::from_be_bytes(buf);
    assert_eq!(magic, FAT_MAGIC);

    f.read_exact(&mut buf)?;
    let nfat_arch = u32::from_be_bytes(buf);

    let mut archs = Vec::new();
    for _ in 0..nfat_arch {
        let arch = parse_fat_arch(f)?;
        archs.push(arch);
    }

    Ok(FatHeader { magic, archs })
}

fn parse_fat_arch(f: &mut File) -> anyhow::Result<FatArch> {
    let mut bytes = [0u8; 4];

    f.read_exact(&mut bytes)?;
    let cputype = i32::from_be_bytes(bytes);
    f.read_exact(&mut bytes)?;
    let cpusubtype = i32::from_be_bytes(bytes);
    f.read_exact(&mut bytes)?;
    let offset = u32::from_be_bytes(bytes) as u64;
    f.read_exact(&mut bytes)?;
    let size = u32::from_be_bytes(bytes) as u64;
    f.read_exact(&mut bytes)?;
    let align = u32::from_be_bytes(bytes);

    Ok(FatArch {
        cputype,
        cpusubtype,
        offset,
        size,
        align,
    })
}

fn parse_mach_header(f: &mut File) -> anyhow::Result<MachHeader> {
    let mut bytes = [0u8; 4];
    f.read_exact(&mut bytes)?;
    let magic = u32::from_ne_bytes(bytes);

    let mut cputype = 0;
    let mut cpusubtype = 0;
    let mut filetype = 0;
    let mut ncmds = 0;
    let mut sizeofcmds = 0;
    let mut flags = 0;

    if magic == MH_MAGIC_64 || magic == MH_MAGIC {
        // Little endian
        f.read_exact(&mut bytes)?;
        cputype = i32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        cpusubtype = i32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        filetype = u32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        ncmds = u32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        sizeofcmds = u32::from_le_bytes(bytes);
        f.read_exact(&mut bytes)?;
        flags = u32::from_le_bytes(bytes);
    } else if magic == MH_CIGAM_64 || magic == MH_CIGAM {
        // Big endian
        f.read_exact(&mut bytes)?;
        cputype = i32::from_be_bytes(bytes);
        f.read_exact(&mut bytes)?;
        cpusubtype = i32::from_be_bytes(bytes);
        f.read_exact(&mut bytes)?;
        filetype = u32::from_be_bytes(bytes);
        f.read_exact(&mut bytes)?;
        ncmds = u32::from_be_bytes(bytes);
        f.read_exact(&mut bytes)?;
        sizeofcmds = u32::from_be_bytes(bytes);
        f.read_exact(&mut bytes)?;
        flags = u32::from_be_bytes(bytes);
    }

    if cputype & CPU_ARCH_ABI64 != 0 {
        // ignore reserved
        f.seek(std::io::SeekFrom::Current(4))?;
    }

    Ok(MachHeader {
        magic,
        cputype,
        cpusubtype,
        filetype,
        ncmds,
        sizeofcmds,
        flags,
    })
}

#[test]
fn test_decoder() -> anyhow::Result<()> {
    let mut decoder = Decoder::new(
        64,
        &[0x0f, 0x82, 0xce, 0x02, 0x00, 0x00],
        DecoderOptions::NONE,
    );
    let ins = decoder.decode();

    let mut encoder = Encoder::new(64);
    encoder.encode(&ins, 0)?;
    let bin = encoder.take_buffer();
    println!("bin: {:02x?}", bin);

    Ok(())
}
