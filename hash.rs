// hash.rs

use std::path::Path;
use std::fs::File;
use std::io::Read;
use md5::Md5;
use md5::Digest as Md5Digest;
use sha1::Sha1;

pub fn compute_md5<P: AsRef<Path>>(file_path: P) -> String {
    let mut file = File::open(file_path).unwrap();
    let mut buffer = [0; 1024];
    let mut hasher = Md5::new();
    loop {
        let bytes_read = file.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    format!("{:x}", hasher.finalize())
}

pub fn compute_sha1<P: AsRef<Path>>(file_path: P) -> String {
    let mut file = File::open(file_path).unwrap();
    let mut buffer = [0; 1024];
    let mut hasher = Sha1::new();
    loop {
        let bytes_read = file.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    format!("{:x}", hasher.finalize())
}