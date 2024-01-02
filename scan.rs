// scan.rs

use std::path::Path;
use std::fs;
use crate::hash::{compute_md5, compute_sha1};
use std::collections::HashMap;

pub fn scan_file<P: AsRef<Path>>(
    file_path: P,
    db_md5: &HashMap<String, String>,
    db_sha1: &HashMap<String, String>,
    db_virusshare: &HashMap<String, String>,
    db_malsharesha1: &HashMap<String, String>,
) -> (bool, u64) {
    let metadata = fs::metadata(&file_path).unwrap();
    let file_size = metadata.len();
    if file_size == 0 {
        println!("{}: Empty file", file_path.as_ref().display());
        return (false, 0);
    }

    let file_hash_md5 = compute_md5(&file_path);
    let file_hash_sha1 = compute_sha1(&file_path);

    let md5_infected = db_md5.get(&file_hash_md5).is_some();
    let sha1_infected = db_sha1.get(&file_hash_sha1).is_some();
    let virusshare_infected = db_virusshare.get(&file_hash_md5).is_some();
    let malsharesha1_infected = db_malsharesha1.get(&file_hash_sha1).is_some();

    if md5_infected || sha1_infected || virusshare_infected || malsharesha1_infected {
        let virus_name = if md5_infected {
            db_md5[&file_hash_md5].as_str()
        } else if sha1_infected {
            db_sha1[&file_hash_sha1].as_str()
        } else if virusshare_infected {
            "FOUND virusshare"
        } else {
            "FOUND malsharesha1"
        };

        println!(
            "FOUND: {} - {}",
            file_path.as_ref().display(),
            virus_name
        );

        (true, file_size)
    } else {
        println!("{}: OK", file_path.as_ref().display());
        (false, file_size)
    }
}

pub fn scan_directory<P: AsRef<Path>>(
    dir_path: P,
    db_md5: &HashMap<String, String>,
    db_sha1: &HashMap<String, String>,
    db_virusshare: &HashMap<String, String>,
    db_malsharesha1: &HashMap<String, String>,
) -> (usize, usize, usize, u64) {
    let mut scanned_files = 0;
    let mut infected_files = 0;
    let mut scanned_directories = 0;
    let mut data_scanned = 0;

    for entry in fs::read_dir(dir_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            let (dir_files, dir_infected, dir_directories, dir_data_scanned) =
                scan_directory(&path, db_md5, db_sha1, db_virusshare, db_malsharesha1);
            scanned_files += dir_files;
            infected_files += dir_infected;
            scanned_directories += dir_directories;
            data_scanned += dir_data_scanned;
        } else {
            let message = format!("Scanning: {}", path.display());
            println!("{}", message);
            let (infected, file_size) = scan_file(&path, db_md5, db_sha1, db_virusshare, db_malsharesha1);
            if infected {
                infected_files += 1;
            }
            scanned_files += 1;
            data_scanned += file_size;
        }
    }

    scanned_directories += 1;

    (scanned_files, infected_files, scanned_directories, data_scanned)
}