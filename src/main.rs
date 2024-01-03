// main.rs

mod scan {
    include!("scan.rs");
}

mod hash {
    include!("hash.rs");
}

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::time::Instant;
use scan::{scan_file, scan_directory};
use std::io::{Result, Lines, BufReader, BufRead};
use std::fs::File;
use chrono::prelude::*;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use num_cpus;

fn main() {
    // Configure Rayon to use all available CPU cores
    let num_cpus = num_cpus::get();
    ThreadPoolBuilder::new().num_threads(num_cpus).build_global().unwrap();

    let start_time = Instant::now();
    let start_date = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1].starts_with('-') {
        print_help();
        std::process::exit(1);
    }

    let path = &args[1];

    let mut db_md5 = HashMap::new();
    let mut db_sha1 = HashMap::new();
    let mut db_virusshare = HashMap::new();
    let mut db_malsharesha1 = HashMap::new();  // New HashMap for malsharesha1

    println!("Loading signatures...");

    // Load md5 signatures
    if let Some(lines_result) = read_lines(&["./database/md5_db.txt"], &["md5_db"]).pop() {
        if let Ok(lines) = lines_result {
            for line in lines {
                if let Ok(record) = line {
                    let parts: Vec<&str> = record.split(':').collect();
                    if let Some(hash) = parts.get(1) {
                        db_md5.insert(parts[0].to_string(), hash.to_string());
                    }
                }
            }
        } else {
            eprintln!("Error loading md5_db signatures");
        }
    }

    // Load sha1 signatures
    if let Some(lines_result) = read_lines(&["./database/sha1_db.txt"], &["sha1_db"]).pop() {
        if let Ok(lines) = lines_result {
            for line in lines {
                if let Ok(record) = line {
                    let parts: Vec<&str> = record.split(':').collect();
                    if let Some(hash) = parts.get(1) {
                        db_sha1.insert(parts[0].to_string(), hash.to_string());
                    }
                }
            }
        } else {
            eprintln!("Error loading sha1_db signatures");
        }
    }

    // Load virusshare signatures
    if let Some(lines_result) = read_lines(&["./database/virusshare.txt"], &["virusshare"]).pop() {
        if let Ok(lines) = lines_result {
            for line in lines {
                if let Ok(record) = line {
                    db_virusshare.insert(record.trim().to_string(), "virusshare".to_string());
                }
            }
        } else {
            eprintln!("Error loading virusshare signatures");
        }
    }

    // Load malsharesha1 signatures
    if let Some(lines_result) = read_lines(&["./database/malsharesha1.txt"], &["malsharesha1"]).pop() {
        if let Ok(lines) = lines_result {
            for line in lines {
                if let Ok(record) = line {
                    db_malsharesha1.insert(record.trim().to_string(), "malsharesha1".to_string());
                }
            }
        } else {
            eprintln!("Error loading malsharesha1 signatures");
        }
    }

    println!("Total loaded signatures: {}", db_md5.len() + db_sha1.len() + db_virusshare.len() + db_malsharesha1.len());

    let (scanned_files, infected_files, scanned_directories, data_scanned) =
        if Path::new(path).is_dir() {
            scan_directory(path, &db_md5, &db_sha1, &db_virusshare, &db_malsharesha1)
        } else {
            let (infected, data_size) = scan_file(path, &db_md5, &db_sha1, &db_virusshare, &db_malsharesha1);
            (1, if infected { 1 } else { 0 }, 0, data_size)
        };

    let elapsed_time = start_time.elapsed();
    let end_date = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    println!("----------- SCAN SUMMARY -----------");
    println!("Known viruses: {}", db_md5.len() + db_sha1.len() + db_virusshare.len() + db_malsharesha1.len());
    println!("Engine version: 0.1.0");
    println!("Scanned directories: {}", scanned_directories);
    println!("Scanned files: {}", scanned_files);
    println!("Infected files: {}", infected_files);
    println!("Data scanned: {:.2} MB", data_scanned as f64 / 1_000_000.0);
    println!(
        "Data read: {:.2} MB (ratio 1.04:1)",
        data_scanned as f64 / 1_000_000.0
    );
    println!("Time: {:.3} sec", elapsed_time.as_secs_f64());
    println!("Start Date: {}", start_date);
    println!("End Date: {}", end_date);

    println!("Scan completed. Exiting...");
    std::process::exit(0);
}

fn print_help() {
    println!("Hydra Dragon AntiVirus: Scanner 0.1.0");
    println!("(C) 2024 By The Emirhan Ucan");
    println!();
    println!("Usage:");
    println!("    HydraDragonAV [options] [file/directory/-]");
    println!();
    println!("Options:");
    println!("    --help                -h             Show this help");
}

fn read_lines<P>(filenames: &[P], signature_types: &[&str]) -> Vec<Result<Lines<BufReader<File>>>>
where
    P: AsRef<Path> + Clone + Send + Sync,
{
    filenames
        .par_iter()
        .zip(signature_types.par_iter())
        .map(|(filename, signature_type)| {
            read_lines_single(filename, signature_type)
        })
        .collect()
}

fn read_lines_single<P>(filename: &P, signature_type: &str) -> Result<Lines<BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let loading_message = format!("Loading {} signatures...", signature_type);
    println!("{}", loading_message);

    Ok(BufReader::new(file).lines())
}
