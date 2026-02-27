use std::env;
use std::fs::File;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <device> [keyslot]", args[0]);
        process::exit(1);
    }

    let device_path = &args[1];
    let mut file = File::open(device_path).unwrap_or_else(|e| {
        eprintln!("Error opening {}: {}", device_path, e);
        process::exit(1);
    });

    let device = match luks::LuksHeader::open(&mut file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error opening LUKS device: {}", e);
            process::exit(1);
        }
    };

    let passphrase = rpassword::prompt_password("Enter passphrase: ").unwrap();
    println!("passphrase is \"{}\"", passphrase);
    let passphrase_bytes = passphrase.as_bytes();

    if args.len() > 2 {
        let keyslot_id = &args[2];
        match device.verify(keyslot_id, passphrase_bytes) {
            Ok(true) => println!("Passphrase verified successfully for keyslot {}!", keyslot_id),
            Ok(false) => println!("Passphrase verification failed for keyslot {}.", keyslot_id),
            Err(e) => {
                eprintln!("Error verifying passphrase: {}", e);
                process::exit(1);
            }
        }
    } else {
        println!("No keyslot specified, trying all keyslots...");
        let mut ids: Vec<_> = device.keyslots.keys().cloned().collect();
        ids.sort();

        let mut found = false;
        for id in ids {
            match device.verify(&id, passphrase_bytes) {
                Ok(true) => {
                    println!("Passphrase verified successfully for keyslot {}!", id);
                    found = true;
                    break;
                }
                Ok(false) => continue,
                Err(e) => {
                    eprintln!("Error verifying keyslot {}: {}", id, e);
                }
            }
        }
        if !found {
            println!("Passphrase could not be verified for any keyslot.");
        }
    }
}
