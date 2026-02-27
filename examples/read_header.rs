use luks::LuksHeader;
use std::env;
use std::fs::File;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <device>", args[0]);
        process::exit(1);
    }

    let device_path = &args[1];
    let file = File::open(device_path).unwrap_or_else(|e| {
        eprintln!("Error opening {}: {}", device_path, e);
        process::exit(1);
    });

    match LuksHeader::from_reader(file) {
        Ok(LuksHeader::V1) => println!("LUKS1 detected on {}", device_path),
        Ok(LuksHeader::V2(h)) => {
            println!("LUKS2 detected on {}", device_path);
            println!("  Label:         {}", h.label);
            println!("  UUID:          {}", h.uuid);
            println!("  Subsystem:     {}", h.subsystem);
            println!("  Checksum Alg:  {}", h.checksum_alg);
            println!("  Header Size:   {}", h.hdr_size);
            println!("  Keyslots:      {}", h.num_keyslots());
            for (id, slot) in &h.metadata.keyslots {
                match slot {
                    luks::Luks2Keyslot::Luks2 {
                        priority, area, kdf, ..
                    } => {
                        println!("    Keyslot {}:", id);
                        println!("      Type:         luks2");
                        if let Some(p) = priority {
                            println!("      Priority:     {:?}", p);
                        }
                        print_area(area);
                        print_kdf(kdf);
                    }
                    luks::Luks2Keyslot::Reencrypt {
                        mode,
                        priority,
                        area,
                        kdf,
                        ..
                    } => {
                        println!("    Keyslot {}:", id);
                        println!("      Type:         reencrypt");
                        println!("      Mode:         {:?}", mode);
                        if let Some(p) = priority {
                            println!("      Priority:     {:?}", p);
                        }
                        print_area(area);
                        print_kdf(kdf);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading LUKS header: {}", e);
            process::exit(1);
        }
    }
}

fn print_area(area: &luks::Luks2Area) {
    println!("      Area:");
    match area {
        luks::Luks2Area::Raw {
            encryption,
            key_size,
            offset,
            size,
        } => {
            println!("        Type:       raw");
            println!("        Encryption: {}", encryption);
            println!("        Key Size:   {:?}", key_size);
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::None { offset, size } => {
            println!("        Type:       none");
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::Journal { offset, size } => {
            println!("        Type:       journal");
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::Checksum {
            offset,
            size,
            hash,
            sector_size,
        } => {
            println!("        Type:       checksum");
            println!("        Hash:       {}", hash);
            println!("        Sector Size:{}", sector_size);
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::Datashift {
            offset,
            size,
            shift_size,
        } => {
            println!("        Type:       datashift");
            println!("        Shift Size: {}", shift_size.0);
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::DatashiftJournal {
            offset,
            size,
            shift_size,
        } => {
            println!("        Type:       datashift-journal");
            println!("        Shift Size: {}", shift_size.0);
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
        luks::Luks2Area::DatashiftChecksum {
            offset,
            size,
            hash,
            sector_size,
            shift_size,
        } => {
            println!("        Type:       datashift-checksum");
            println!("        Hash:       {}", hash);
            println!("        Sector Size:{}", sector_size);
            println!("        Shift Size: {}", shift_size.0);
            println!("        Offset:     {}", offset.0);
            println!("        Size:       {}", size.0);
        }
    }
}

fn print_kdf(kdf: &luks::Luks2Kdf) {
    println!("      KDF:");
    match kdf {
        luks::Luks2Kdf::Argon2i {
            time,
            memory,
            cpus,
            salt,
        } => {
            println!("        Type:       argon2i");
            println!("        Time:       {}", time);
            println!("        Memory:     {}", memory);
            println!("        CPUs:       {}", cpus);
            println!("        Salt:       {}", salt);
        }
        luks::Luks2Kdf::Argon2id {
            time,
            memory,
            cpus,
            salt,
        } => {
            println!("        Type:       argon2id");
            println!("        Time:       {}", time);
            println!("        Memory:     {}", memory);
            println!("        CPUs:       {}", cpus);
            println!("        Salt:       {}", salt);
        }
        luks::Luks2Kdf::Pbkdf2 {
            hash,
            iterations,
            salt,
        } => {
            println!("        Type:       pbkdf2");
            println!("        Hash:       {}", hash);
            println!("        Iterations: {}", iterations);
            println!("        Salt:       {}", salt);
        }
    }
}
