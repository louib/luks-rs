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

    match LuksHeader::open(file) {
        Ok(device) => {
            let json = serde_json::to_string_pretty(&device).unwrap();
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Error opening LUKS device: {}", e);
            process::exit(1);
        }
    }
}
