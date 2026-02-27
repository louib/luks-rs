use luks::LuksDevice;
use std::env;
use std::io;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <fixture_json> [keyslot]", args[0]);
        process::exit(1);
    }

    let fixture_path = &args[1];
    let fixture_str = std::fs::read_to_string(fixture_path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", fixture_path, e);
        process::exit(1);
    });

    let device: LuksDevice = serde_json::from_str(&fixture_str).unwrap_or_else(|e| {
        eprintln!("Error deserializing fixture: {}", e);
        process::exit(1);
    });

    eprint!("Enter passphrase: ");
    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase).unwrap();
    // Trim only the trailing newline/carriage return, keeping intentional spaces
    if passphrase.ends_with('\n') {
        passphrase.pop();
    }
    if passphrase.ends_with('\r') {
        passphrase.pop();
    }
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
