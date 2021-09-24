use std::collections::HashMap;
use std::io::Error;
use walkdir::{WalkDir, DirEntry};
use clap::{Arg, App, SubCommand};
use std::fs;
use std::io::{BufReader, Read};
use sha2::{Digest, Sha256};
use digest::generic_array::GenericArray;

//Retrieve informations from Cargo.toml file
const APPNAME: &'static str = env!("CARGO_PKG_NAME");
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &'static str = env!("CARGO_PKG_DESCRIPTION");

//Buffer size for the hash processing
const BUFFER_SIZE: usize = 1024;

/*
 * Constants for hash skipping
 * TODO: provide the values through arguments
 */
const SMALL_FILE_SIZE: u64 = 1024 * 1024 * 8; // 1 Mb
const BIG_FILE_SIZE: u64 = 1024 * SMALL_FILE_SIZE; // 1 Gb

fn main() -> Result<(), Error> {
    let app = App::new(APPNAME)
                    .version(VERSION)
                    .about(DESCRIPTION)
                    .subcommand(SubCommand::with_name("n")
                        .about("Compare through file names only"))
                    .subcommand(SubCommand::with_name("s")
                        .about("Compare through file names and sizes"))
                    .subcommand(SubCommand::with_name("h")
                        .about("Compare through file hashes (using sha256, pretty slow)")
                        .arg(Arg::with_name("big-files")
                            .short("b")
                            .help("skip big files (> 1Gb)"))
                        .arg(Arg::with_name("small-files")
                            .short("s")
                            .help("skip small files (< 1 Mb)")))
                    .arg(Arg::with_name("DIRECTORY")
                        .help("Root directory from which to search the files")
                        .global(true)
                        .default_value("."));
                    
    let matches = app.get_matches();
            

    //Iterate over every file that can be seen and filter out the directories
    let iter = WalkDir::new(matches.value_of("DIRECTORY").unwrap_or_default())
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir());
    
    match matches.subcommand(){
        ("n", Some(_)) => { file_names(iter) },
        ("s", Some(_)) => { file_names_sizes(iter) },
        ("h", Some(hash)) => { 
            file_hashes(iter, hash.is_present("big-files"), hash.is_present("small-files")) 
        },
        _ => { 
            eprintln!("Wrong subcommand specified");
            std::process::exit(1);
        },
    }   
}

fn file_names<'a, I>(iter: I) -> Result<(), Error> 
where I: IntoIterator<Item= DirEntry>,
{
    let mut filenames : HashMap<String, Vec<DirEntry>> = HashMap::new();
    for entry in iter.into_iter() {
        let f_name = String::from(entry.file_name().to_string_lossy());
        let counter = filenames.entry(f_name).or_insert(Vec::new());
        counter.push(entry);
    }
    for files in filenames.into_iter().filter(|e| e.1.len() != 1) {
        println!("{filename}:",filename=files.0);
        for f in files.1.into_iter() {
            println!("\t{filepath}",filepath=f.path().to_string_lossy());
        }
    }
    Ok(())
}

fn file_names_sizes<'a, I>(iter: I) -> Result<(), Error> 
where I: IntoIterator<Item= DirEntry>,
{
    let mut filenames : HashMap<(String,u64), Vec<DirEntry>> = HashMap::new();
    for entry in iter.into_iter() {
        let f_name = String::from(entry.file_name().to_string_lossy());
        let f_size = entry.metadata()?.len();
        let counter = filenames.entry((f_name,f_size)).or_insert(Vec::new());
        counter.push(entry);
    }
    for files in filenames.into_iter().filter(|e| e.1.len() != 1) {
        println!("{filename}:",filename=files.0.0);
        for f in files.1.into_iter() {
            println!("\t{filepath}",filepath=f.path().to_string_lossy());
        }
    }
    Ok(())
}

fn file_hashes<'a, I>(iter: I, bigfile: bool, smallfile: bool) -> Result<(), Error> 
where I: IntoIterator<Item= DirEntry>,
{
    let mut filenames : HashMap<(String,u64, GenericArray<u8, <sha2::Sha256 as Digest>::OutputSize>), Vec<DirEntry>> = HashMap::new();
    for entry in iter.into_iter() {
        let f_name = String::from(entry.file_name().to_string_lossy());
        let f_size = entry.metadata()?.len();
        if (bigfile && f_size > BIG_FILE_SIZE) || (smallfile && f_size < SMALL_FILE_SIZE) {
            continue
        }
        let file = fs::File::open(entry.path())?;
        let mut reader = BufReader::new(file);
        let f_hash = process::<Sha256,_>(&mut reader)?;
        let counter = filenames.entry((f_name,f_size, f_hash)).or_insert(Vec::new());
        counter.push(entry);
    }
    for files in filenames.into_iter().filter(|e| e.1.len() != 1) {
        println!("{filename}:",filename=files.0.0);
        for f in files.1.into_iter() {
            println!("\t{filepath}",filepath=f.path().to_string_lossy());
        }
    }
    Ok(())
}

// provided by https://github.com/RustCrypto/hashes/blob/master/sha2/examples/sha256sum.rs
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Result<GenericArray<u8, <D as Digest>::OutputSize>, Error>{
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    Ok(sh.finalize())
}
