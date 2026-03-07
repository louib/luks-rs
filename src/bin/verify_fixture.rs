use luks::{Key, LuksDevice};
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

    let mut device: LuksDevice = serde_json::from_str(&fixture_str).unwrap_or_else(|e| {
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
    let key = Key::from(passphrase);

    if args.len() > 2 {
        let keyslot_id = &args[2];
        match device.unlock(keyslot_id, &key) {
            Ok(_) => println!("Passphrase verified successfully for keyslot {}!", keyslot_id),
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
            match device.unlock(&id, &key) {
                Ok(_) => {
                    println!("Passphrase verified successfully for keyslot {}!", id);
                    found = true;
                    break;
                }
                Err(_) => continue,
            }
        }
        if !found {
            println!("Passphrase could not be verified for any keyslot.");
        }
    }
}
