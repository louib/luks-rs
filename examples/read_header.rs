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
        }
        Err(e) => {
            eprintln!("Error reading LUKS header: {}", e);
            process::exit(1);
        }
    }
}
