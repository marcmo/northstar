// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#![deny(clippy::all)]

use anyhow::{anyhow, Context, Error, Result};
use fs_extra::dir::{copy, CopyOptions};
use itertools::Itertools;
use log::debug;
use log::info;
use north_common::manifest::Manifest;
use rand::{AsByteSliceMut, RngCore};
use serde_yaml;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::SecretKey;
use sodiumoxide::crypto::sign::{keypair_from_seed, sign, Seed, Signature, SEEDBYTES};
use std::fs::File;
use std::io::SeekFrom::Start;
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;
use std::process::Command;
use std::{fs, io, path::PathBuf, str::FromStr};
use structopt::StructOpt;
use tempdir::TempDir;
use uuid::Uuid;
use zip::write::FileOptions;

#[derive(Debug)]
enum Format {
    Text,
    Json,
}

impl FromStr for Format {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Format::Json),
            "text" | "txt" => Ok(Format::Text),
            _ => Err(anyhow!("Invalid format {}", s)),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Unpack Northstar containers
    Unpack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        /// Container to inspect
        #[structopt(short, long)]
        container: PathBuf,
        /// Output format
        #[structopt(short, long)]
        format: Format,
    },
}

// TODO: all from here: move to its own file

const DIGEST_SIZE: usize = 32;
const BLOCK_SIZE: u64 = 4096;

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    info!("{:#?}", opt);
    match opt {
        Opt::Pack { dir, out } => pack_cmd(&dir, &out),
        _ => {
            unimplemented!();
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
enum FsType {
    SQUASHFS,
    EXT4,
}

fn pack_cmd(_dir: &Path, _out: &Path) -> Result<()> {
    let current_dir = std::env::current_dir()?;
    let example_dir = current_dir.join("examples");
    let container_src_dir = example_dir.join("container");
    let key_dir = example_dir.join("keys");
    let registry_dir = current_dir.join("target").join("north").join("registry");

    pack_containers(
        &registry_dir,
        &container_src_dir,
        &key_dir,
        "north",
        FsType::SQUASHFS,
        1000,
        1000,
    )
}

fn pack_containers(
    registry_dir: &Path,
    container_src_dir: &Path,
    key_dir: &Path,
    signing_key_name: &str,
    fs_type: FsType,
    uid: u32,
    gid: u32,
) -> Result<()> {
    debug!("");
    debug!("pack_containers called with");
    debug!("registry_dir={}", registry_dir.display());
    debug!("container_src_dir={}", container_src_dir.display());
    debug!("key_dir={}", key_dir.display());
    debug!("signing_key_name={}", signing_key_name);

    // read signing key
    let sign_key_path = key_dir.join(signing_key_name).with_extension("key");
    debug!("opening file {}", sign_key_path.display());
    let mut sign_key_file = File::open(&sign_key_path)?;
    let tmp = sign_key_file.metadata()?;
    debug!(
        "sign_key_file.len()={}",
        sign_key_file.metadata().unwrap().len()
    );
    let mut raw_signing_key_seed = [0u8; SEEDBYTES];
    let read_bytes = sign_key_file.read(&mut raw_signing_key_seed)?;
    debug!("read_bytes={}", read_bytes);
    debug!("signing_key_seed={:02x?}", raw_signing_key_seed.to_vec());
    let signing_key_seed =
        Seed::from_slice(&raw_signing_key_seed).ok_or(anyhow!("Cannot parse seed"))?;
    let (_, signing_key) = keypair_from_seed(&signing_key_seed);

    let mut src_dirs = fs::read_dir(container_src_dir)?
        .map(|res| res.map(|e| e.path()))
        .filter_map(Result::ok)
        .filter(|mut r| r.join("manifest.yaml").exists())
        .collect::<Vec<_>>();
    src_dirs.sort();
    for src_dir in src_dirs {
        pack(&src_dir, &registry_dir, &signing_key, fs_type, uid, gid)?;
    }

    Ok(())
}

fn pack(
    src_dir: &Path,
    registry_dir: &Path,
    signing_key: &SecretKey,
    fs_type: FsType,
    uid: u32,
    gid: u32,
) -> Result<()> {
    let component_name = src_dir
        .components()
        .last()
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap();
    debug!("");
    debug!("Packing '{}'", component_name);
    debug!("src_dir={}", src_dir.display());
    debug!("registry_dir={}", registry_dir.display());

    // load manifest
    let manifest_file_path = src_dir.join("manifest").with_extension("yaml");
    let arch = "x86_64-unknown-linux-gnu"; // TODO: get as CLI parameter
    let manifest_file = std::fs::File::open(&manifest_file_path)?;
    debug!("read manifest file {}", manifest_file_path.display());
    let manifest: Manifest = serde_yaml::from_reader(manifest_file)
        .with_context(|| format!("Failed to parse {}", manifest_file_path.display()))?;

    let tmp_dir =
        TempDir::new("").with_context(|| format!("Could not create temporary directory"))?;

    debug!("find {}:", tmp_dir.path().display());
    debug!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // copy root
    debug!("copy root:");
    let root_dir = src_dir.join("root");
    let options = CopyOptions::new();
    let tmp_root_dir = tmp_dir.path().join("root");
    if root_dir.exists() {
        debug!(
            "copy {} to {}",
            root_dir.display(),
            tmp_dir.path().display()
        );
        copy(&root_dir, &tmp_dir, &options)?;
    }
    if !tmp_root_dir.exists() {
        debug!("mkdir {}", tmp_root_dir.display());
        fs::create_dir(&tmp_root_dir)
            .with_context(|| format!("Could not create temporary directory"))?;
    }

    debug!("find {}:", tmp_dir.path().display());
    debug!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // copy arch specific root
    debug!("copy arch specific root:");
    let arch_dir = src_dir.join(format!("root-{}", arch));
    debug!("arch_dir={}", arch_dir.display());
    if arch_dir.exists() {
        let arc_spec_files = fs::read_dir(arch_dir)?
            .map(|res| res.map(|e| e.path()))
            .filter_map(Result::ok)
            .collect::<Vec<PathBuf>>();
        debug!("arc_spec_dirs.len()={}", arc_spec_files.len());
        for arc_spec_file in arc_spec_files {
            debug!(
                "copy {} to {}",
                arc_spec_file.display(),
                tmp_root_dir.display()
            );
            // TODO: we assume copying a file and not a directory
            std::fs::copy(
                &arc_spec_file,
                &tmp_root_dir.join(arc_spec_file.file_name().unwrap()),
            )?;
            // fs_extra::dir::copy(&arc_spec_file, &tmp_root_dir, &options)?;
        }
    }

    debug!("find {}:", tmp_dir.path().display());
    debug!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // write manifest
    debug!("write manifest");
    let tmp_manifest_dir = tmp_dir.path().join("manifest").with_extension("yaml");
    debug!("create file {}", tmp_manifest_dir.display());
    let tmp_manifest_file = File::create(&tmp_manifest_dir)?;
    debug!("writing file {}", tmp_manifest_dir.display());
    serde_yaml::to_writer(tmp_manifest_file, &manifest)?;

    // remove existing containers
    // TODO: remove all {registry}/#{name}-#{arch}-* directories

    let fsimg_path = &tmp_dir.path().join("fs").with_extension("img");

    /* The list of pseudo files is target specific.
     * Add /lib and lib64 on Linux systems.
     * Add /system on Android. */
    let mut pseudo_files = vec![
        ("/tmp", 444),
        ("/proc", 444),
        ("/dev", 444),
        ("/sys", 444),
        ("/data", 777),
    ];
    if arch == "aarch64-unknown-linux-gnu" || arch == "x86_64-unknown-linux-gnu" {
        pseudo_files.push(("/lib", 444));
        pseudo_files.push(("/lib64", 444));
    } else if arch == "aarch64-linux-android" {
        pseudo_files.push(("/system", 444));
    }

    // create filesystem image
    let squashfs_comp = match std::env::consts::OS {
        "linux" => "gzip",
        _ => "zstd",
    };
    if fs_type == FsType::SQUASHFS {
        let mut cmd = Command::new("mksquashfs");
        cmd.arg(tmp_root_dir.as_os_str().to_str().unwrap())
            .arg(fsimg_path.as_os_str().to_str().unwrap())
            .arg("-all-root")
            .arg("-comp")
            .arg(squashfs_comp)
            .arg("-no-progress")
            .arg("-info");
        for pseudo_file in pseudo_files {
            cmd.arg("-p");
            cmd.arg(format!(
                "{} d {} {} {}",
                pseudo_file.0,
                pseudo_file.1.to_string(),
                uid,
                gid
            ));
        }
        dbg!(&cmd);
        let cmd_output = cmd.output()?;
        debug!("status={}", cmd_output.status);
        debug!("stdout={}", String::from_utf8_lossy(&cmd_output.stdout));
        debug!("stderr={}", String::from_utf8_lossy(&cmd_output.stderr));
    } else if fs_type == FsType::EXT4 {
        unimplemented!()
    } else {
        unimplemented!() // unknown file type
    }
    debug!("fsimg_path={}", fsimg_path.as_os_str().to_str().unwrap());
    let filesystem_size = fs::metadata(fsimg_path)?.len();

    // append verity header and hash tree to filesystem image
    assert_eq!(filesystem_size % BLOCK_SIZE, 0);
    let data_blocks: u64 = filesystem_size / BLOCK_SIZE;
    debug!("data_blocks={}", &data_blocks);
    let uuid = Uuid::new_v4();
    debug!("uuid={}", &uuid);
    debug!(
        "uuid_decoded={:?}",
        hex::decode(uuid.to_string().replace("-", ""))
    );
    let mut salt = [0u8; DIGEST_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    debug!("filesystem_size={}", filesystem_size);
    debug!("BLOCK_SIZE={}", BLOCK_SIZE);
    debug!("DIGEST_SIZE={}", DIGEST_SIZE);
    let (hash_level_offsets, tree_size) = calc_hash_level_offsets(
        filesystem_size as usize,
        BLOCK_SIZE as usize,
        DIGEST_SIZE as usize,
    );
    debug!("tree_size={}", tree_size);
    debug!("hash_level_offsets.len()={}", hash_level_offsets.len());
    for hash_level_offset in &hash_level_offsets {
        debug!("hash_level_offset={}", hash_level_offset);
    }

    let mut fsimg = File::open(&fsimg_path)?;
    let (verity_hash, hash_tree) = generate_hash_tree(
        &fsimg,
        filesystem_size,
        BLOCK_SIZE,
        &salt,
        &hash_level_offsets,
        tree_size,
    );
    debug!("verity_hash.len()={}", verity_hash.len());
    debug!("hash_tree.len()={}", hash_tree.len());

    /* ['verity', 1, 1, uuid.gsub('-', ''), 'sha256', 4096, 4096, data_blocks, 32, salt, '']
     * .pack('a8 L L H32 a32 L L Q S x6 a256 a3752')
     * (https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format)
     * (https://ruby-doc.org/core-2.7.1/Array.html#method-i-pack) */
    fsimg.seek(Start(filesystem_size));
    fsimg.write("verity".as_bytes());
    fsimg.write(&[0_u8, 0_u8]);
    fsimg.write(&1_u32.to_ne_bytes());
    fsimg.write(&1_u32.to_ne_bytes());
    fsimg.write(&hex::decode(uuid.to_string().replace("-", ""))?);
    fsimg.write("sha256".as_bytes());
    fsimg.write(&vec![0_u8; 26]);
    fsimg.write(&4096_u32.to_ne_bytes());
    fsimg.write(&4096_u32.to_ne_bytes());
    fsimg.write(&data_blocks.to_ne_bytes());
    fsimg.write(&32_u16.to_ne_bytes());
    fsimg.write(&vec![0_u8; 6]);
    fsimg.write(&salt);
    fsimg.write(&vec![0_u8; 256 - salt.len()]);
    fsimg.write(&vec![0_u8; 3752]);

    fsimg.write(&hash_tree);
    fsimg.flush();

    // create hashes YAML
    let mut sha256 = Sha256::new();
    io::copy(&mut File::open(&tmp_manifest_dir)?, &mut sha256)?;
    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    fsimg.seek(Start(0)); // return to start of file before hashing
    io::copy(&mut fsimg, &mut sha256)?;

    let fs_hash = sha256.finalize();
    let hashes = format!(
        "manifest.yaml:\n  hash: {:02x?}\n\
         fs.img:\n  hash: {:02x?}\n  verity-hash: {:02x?}\n  verity-offset: {}\n",
        manifest_hash.iter().format(""),
        fs_hash.iter().format(""),
        verity_hash.iter().format(""),
        filesystem_size
    );
    debug!("hashes=\n{}", hashes);

    // sign hashes
    let signature = sign::sign_detached(hashes.as_bytes(), &signing_key);
    debug!("signature.as_ref().len()={}", signature.as_ref().len());
    let signature_base64 = base64::encode(signature);
    let key_id = "north";
    let signatures = format!(
        "{}---\nkey: {}\nsignature: {}",
        &hashes, &key_id, &signature_base64
    );
    debug!("signatures=\n{}", &signatures);

    // create zip
    debug!("manifest.version={}", manifest.version);
    let npk_dir = registry_dir
        .join(format!("{}-{}-{}.", manifest.name, arch, manifest.version))
        .with_extension("npk");
    debug!("npk_dir=\n{}", &npk_dir.display());
    let mut npk_file = File::create(&npk_dir)?;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(&npk_file);
    zip.start_file("signature.yaml", options);
    zip.write(signatures.as_bytes());
    zip.start_file("manifest.yaml", options);
    let manifest_string = serde_yaml::to_string(&manifest)?;
    zip.write(manifest_string.as_bytes());

    let offset = 43 + manifest_string.len() + 44 + signatures.len() + 36; // stored
    let padding = (offset / 4096 + 1) * 4096 - offset;

    let zeros = vec![0_u8; padding as usize];

    zip.start_file_from_path_with_extra_data(fsimg_path, options, &zeros);
    let mut fsimg = File::open(&fsimg_path)?;
    let mut fsimg_cont: Vec<u8> = vec![0u8; fs::metadata(&fsimg_path).unwrap().len() as usize];
    fsimg.read(&mut fsimg_cont);
    zip.write(&fsimg_cont);

    Ok(())
}

fn calc_hash_level_offsets(
    image_size: usize,
    block_size: usize,
    digest_size: usize,
) -> (Vec<usize>, usize) {
    let mut level_offsets: Vec<usize> = vec![];
    let mut level_sizes: Vec<usize> = vec![];
    let mut tree_size = 0;

    let mut num_levels = 0;
    let mut size = image_size;
    while size > block_size {
        let num_blocks = (size + block_size - 1) / block_size;
        let level_size = round_up_to_multiple(num_blocks * digest_size, block_size);

        level_sizes.push(level_size);
        tree_size += level_size;
        num_levels = num_levels + 1;

        size = level_size;
    }

    for n in 0..num_levels {
        let mut offset = 0;
        for m in (n + 1)..num_levels {
            offset += level_sizes[m];
        }
        level_offsets.push(offset);
    }

    (level_offsets, tree_size)
}

fn generate_hash_tree(
    image: &File,
    image_size: u64,
    block_size: u64,
    salt: &[u8; 32],
    hash_level_offsets: &Vec<usize>,
    tree_size: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut hash_ret = vec![0_u8; tree_size];
    let hash_src_offset = 0;
    let mut hash_src_size = image_size;
    let mut level_num = 0;
    let mut reader = BufReader::new(image);
    let mut level_output: Vec<u8> = vec![];

    while hash_src_size > block_size {
        let mut level_output_list: Vec<[u8; DIGEST_SIZE]> = vec![];
        let mut remaining = hash_src_size;
        while remaining > 0 {
            let mut sha256 = Sha256::new();
            sha256.update(salt);

            let mut data_len = 0;
            if level_num == 0 {
                let offset = hash_src_offset + hash_src_size - remaining;
                data_len = std::cmp::min(remaining, block_size);
                let mut data = vec![0_u8; data_len as usize];
                reader.seek(Start(offset));
                reader.read(&mut data);
                sha256.update(&data);
            } else {
                let offset =
                    hash_level_offsets[level_num - 1] + hash_src_size as usize - remaining as usize;
                data_len = block_size;
                debug!("offset={}", &offset);
                debug!("data_len={}", &data_len);
                debug!("offset + data_len={}", offset + data_len as usize);
                debug!("tree_size={}", &tree_size);
                debug!("hash_ret.len()={}", hash_ret.len());
                sha256.update(&hash_ret[offset..offset + data_len as usize]);
            }

            remaining = remaining - data_len;
            if data_len < block_size {
                let zeros = vec![0_u8; (block_size - data_len) as usize];
                sha256.update(zeros);
            }
            level_output_list.push(sha256.finalize().into());
        }

        level_output = level_output_list
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        let padding_needed =
            (round_up_to_multiple(level_output.len(), block_size as usize) - level_output.len());
        level_output.append(&mut vec![0_u8; padding_needed]);

        let offset = hash_level_offsets[level_num];
        hash_ret[offset..offset + level_output.len()].copy_from_slice(level_output.as_slice());

        hash_src_size = level_output.len() as u64;
        level_num = level_num + 1;
    }

    let digest = Sha256::digest(
        &salt
            .iter()
            .copied()
            .chain(level_output.iter().copied())
            .collect::<Vec<u8>>(),
    );

    (digest.to_vec(), hash_ret)
}

fn round_up_to_multiple(number: usize, factor: usize) -> usize {
    let round_down_to_multiple = number + factor - 1;
    round_down_to_multiple - (round_down_to_multiple % factor)
}
