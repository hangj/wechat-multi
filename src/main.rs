use std::{
    fs::File,
    io::{Cursor, Read, Seek, Write},
};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Formatter, Instruction, IntelFormatter, Register,
};
use mach_object::{
    LoadCommand, MachCommand, OFile, CPU_SUBTYPE_ARM_ALL, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64,
    CPU_TYPE_X86_64, MH_EXECUTE,
};

use disarm64::{
    decoder::{self, Operation, ADDSUB_IMM, B_ADDR_PCREL26, CONDBRANCH},
    registers::get_int_reg_name,
    Opcode,
};

use memmap::MmapMut;

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        return Err(anyhow::anyhow!("Usage: {} path/to/file", args[0]));
    }

    backup(&args[1])?;

    let mut file = File::options().write(true).read(true).open(&args[1])?;
    // let mmap = unsafe { Mmap::map(&file) }?;
    let mut mmap = unsafe { MmapMut::map_mut(&mut file) }?;
    let payload = mmap.as_mut();
    let mut cur = Cursor::new(payload);
    let ofile = OFile::parse(&mut cur)?;

    process_ofile(&ofile, &mut cur)?;

    Ok(())
}

/// Create a backup file if path.bak doesn't exist
fn backup(path: &str) -> anyhow::Result<()> {
    // check if backup file exists
    let backup_file = format!("{path}.bak");
    if std::path::Path::new(&backup_file).try_exists()? {
        println!("backup file found: {}", backup_file);
        return Ok(());
    }

    println!("backup file creating ...");
    std::fs::copy(path, &backup_file)?;
    println!("backup file created: {}", backup_file);

    Ok(())
}

fn process_ofile(ofile: &OFile, cursor: &mut Cursor<&mut [u8]>) -> anyhow::Result<()> {
    match ofile {
        OFile::FatFile {
            magic: _,
            ref files,
        } => {
            for &(ref arch, ref file) in files {
                cursor.seek(std::io::SeekFrom::Start(arch.offset))?;
                process_ofile(file, cursor)?;
            }
        }
        OFile::MachFile {
            ref header,
            ref commands,
        } => {
            assert_eq!(header.filetype, MH_EXECUTE);
            let posotion = cursor.position();

            // Delete CodeSignature
            // https://keith.github.io/xcode-man-pages/codesign.1.html
            // codesign --remove-signature /Applications/WeChat.app/Contents/MacOS/WeChat
            // codesign --display --verbose=4 /Applications/WeChat.app/Contents/MacOS/WeChat
            if let Some((idx, MachCommand(LoadCommand::CodeSignature(_cs), cmdsize))) = commands
                .iter()
                .enumerate()
                .find(|(_, cmd)| matches!(cmd, MachCommand(LoadCommand::CodeSignature(_), _)))
            {
                // return Err(anyhow::anyhow!(
                //     "You need to remove the code_signature first\n{} '{}'",
                //     "codesign --remove-signature",
                //     std::env::args()
                //         .skip(1)
                //         .next()
                //         .ok_or(anyhow::anyhow!("The path to WeChat is not provided"))?,
                // ));

                let ncmds = header.ncmds - 1;
                let sizeofcmds = header.sizeofcmds - *cmdsize as u32;

                let (ncmds, sizeofcmds) = if header.is_bigend() {
                    (ncmds.to_be_bytes(), sizeofcmds.to_be_bytes())
                } else {
                    (ncmds.to_le_bytes(), sizeofcmds.to_le_bytes())
                };
                // skip magic, cputype, cpusubtype and filetype
                cursor.seek(std::io::SeekFrom::Start(posotion + 16))?;
                cursor.write(&ncmds)?;
                cursor.write(&sizeofcmds)?;

                let pre_cmds_size = commands
                    .iter()
                    .take(idx)
                    .map(|cmd| cmd.size())
                    .sum::<usize>();

                let len = header.sizeofcmds as usize - pre_cmds_size - *cmdsize;
                let mut buf = vec![0u8; len];

                cursor.seek(std::io::SeekFrom::Start(
                    posotion + pre_cmds_size as u64 + *cmdsize as u64,
                ))?;
                cursor.read_exact(&mut buf)?;

                cursor.seek(std::io::SeekFrom::Start(posotion + pre_cmds_size as u64))?;
                cursor.write_all(&buf)?;
            }

            // Find the EntryPoint
            if let Some(LoadCommand::EntryPoint { entryoff, .. }) = commands
                .iter()
                .map(|cmd| cmd.command())
                .find(|cmd| matches!(cmd, LoadCommand::EntryPoint { .. }))
            {
                cursor.seek(std::io::SeekFrom::Start(posotion + *entryoff))?;
            } else {
                return Err(anyhow::anyhow!("No EntryPoint found."));
            }

            if header.cputype == CPU_TYPE_X86_64 && header.cpusubtype == CPU_SUBTYPE_X86_64_ALL {
                x86(cursor)?;
            }

            if header.cputype == CPU_TYPE_ARM64 && header.cpusubtype == CPU_SUBTYPE_ARM_ALL {
                aarch64(cursor)?;
            }
        }
        o => return Err(anyhow::anyhow!("Unsupported ofile format: {:?}", o)),
    }

    Ok(())
}

pub fn x86(cursor: &mut Cursor<&mut [u8]>) -> anyhow::Result<()> {
    let position = cursor.seek(std::io::SeekFrom::Current(0))?;

    let mut text = [0u8; 1024];
    cursor.read_exact(&mut text)?;
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
            && instruction.immediate8() == 2
        {
            // let imm2 = instruction.immediate8_2nd();
            // println!("imm2: {:02x?}", imm2); // 0xd0

            // encoder.encode(&instruction, 0)?;
            // let opcode = encoder.take_buffer();
            // println!("opcode: {:02x?}", opcode);

            output.clear();
            formatter.format(&instruction, &mut output);
            // println!("{}", output);

            let ip = decoder.ip();
            // println!("ip: {:#04x}", ip);

            if decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                if instruction.is_invalid() {
                    break;
                }
                // encoder.encode(&instruction, ip)?;
                // let opcode = encoder.take_buffer();
                // println!("opcode: {:02x?}", opcode);
                // let opcode_len = opcode.len();

                output.clear();
                formatter.format(&instruction, &mut output);
                // println!("{}", output);

                if instruction.code() == Code::Jb_rel32_64 {
                    instruction.set_code(Code::Jmp_rel32_64);
                    encoder.encode(&instruction, ip)?;
                    let opcode = encoder.take_buffer();
                    // println!("new opcode: {:02x?}", opcode);

                    let mut new_instruction = String::new();
                    formatter.format(&instruction, &mut new_instruction);
                    println!("{output} => {new_instruction}");

                    cursor.seek(std::io::SeekFrom::Start(position + ip))?;
                    cursor.write(&opcode)?;

                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

pub fn aarch64(cursor: &mut Cursor<&mut [u8]>) -> anyhow::Result<()> {
    let position = cursor.seek(std::io::SeekFrom::Current(0))?;

    let mut code = [0u8; 512];
    cursor.read_exact(&mut code)?;
    // println!("{:02x?}", code);

    let mut iter = code
        .chunks_exact(4)
        .map(|v| {
            decoder::decode(u32::from_le_bytes(v.try_into().expect("Invalid [u8; 4]")))
                .expect("Invalid instruction")
        })
        .enumerate();

    while let Some((_, Opcode { operation, .. })) = iter.next() {
        // `cmp x21, #0x2` or `subs xzr, x21, #0x2`
        if let Operation::ADDSUB_IMM(ADDSUB_IMM::SUBS_Rd_Rn_SP_AIMM(s)) = operation {
            if get_int_reg_name(true, s.rd() as u8, true) == "xzr" && s.imm12() == 0x2 {
                // println!("Instruction: {insn:?}");
                // println!("Formatted: {insn}");
                // println!("Definition: {:?}", insn.definition());
                // println!("bits: {:02x?} {:02x?}", insn.operation.bits().to_le_bytes(), v);

                // `b.cc 0x22c` or `b.lo 0x22c`
                // https://developer.arm.com/documentation/ddi0602/2024-03/Base-Instructions/B-cond--Branch-conditionally-?lang=en
                if let Some((
                    i,
                    Opcode {
                        operation: Operation::CONDBRANCH(CONDBRANCH::B__ADDR_PCREL19(b)),
                        ..
                    },
                )) = iter.next()
                {
                    if b.cond() == 3 {
                        let imm19 = b.imm19();
                        // println!("{} {}", i*4, imm19);
                        // println!("bits: {:02x?}", insn.bits().to_le_bytes());

                        let branch = B_ADDR_PCREL26::DEFINITION.opcode
                            | B_ADDR_PCREL26::new().with_imm26(imm19).into_bits();

                        let bytes = branch.to_le_bytes();

                        println!(
                            "{} => {}",
                            decoder::decode(b.into_bits()).unwrap(),
                            decoder::decode(branch).unwrap()
                        );
                        cursor.seek(std::io::SeekFrom::Start(position + i as u64 * 4))?;
                        cursor.write(&bytes)?;

                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
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
