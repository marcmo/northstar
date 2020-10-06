use anyhow::{anyhow, Context, Result};
use fs_extra::dir::{copy, CopyOptions};
use itertools::Itertools;
use log::debug;
use north::manifest::Manifest;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{
    sign,
    sign::{ed25519::SecretKey, keypair_from_seed, Seed, SEEDBYTES},
};
use std::{
    fs,
    fs::{File, OpenOptions},
    io,
    io::{BufReader, Read, Seek, SeekFrom::Start, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempdir::TempDir;
use uuid::Uuid;

#[derive(Copy, Clone, PartialEq)]
enum FsType {
    SQUASHFS,
    EXT4,
}

const DIGEST_SIZE: usize = 32;
const BLOCK_SIZE: u64 = 4096;

/// out_dir: where the npk should be packaged to (usually the registry directory)
pub fn pack_cmd(container_src_dir: &Path, out_dir: &Path, key_file: &Path) -> Result<()> {
    pack_containers(
        &out_dir,
        &container_src_dir,
        &key_file,
        FsType::SQUASHFS,
        1000,
        1000,
    )
}

fn pack_containers(
    out_dir: &Path,
    container_src_dir: &Path,
    key_file: &Path,
    fs_type: FsType,
    uid: u32,
    gid: u32,
) -> Result<()> {
    debug!("");
    debug!("pack_containers called with");
    debug!("out_dir={}", out_dir.display());
    debug!("container_src_dir={}", container_src_dir.display());

    // read signing key
    debug!("opening file {}", key_file.display());
    let metadata = key_file
        .metadata()
        .with_context(|| format!("Could not get info for {}", key_file.display()))?;

    if !metadata.is_file() {
        return Err(anyhow!("{} is a directory, not a file", key_file.display()));
    }
    let mut sign_key_file = File::open(&key_file)
        .with_context(|| format!("Key-file did not exist: {}", key_file.display()))?;
    debug!("sign_key_file.len()={}", metadata.len());
    let mut raw_signing_key_seed = [0u8; SEEDBYTES];
    let read_bytes = sign_key_file.read(&mut raw_signing_key_seed)?;
    debug!("read_bytes={}", read_bytes);
    debug!("signing_key_seed={:02x?}", raw_signing_key_seed.to_vec());
    let signing_key_seed =
        Seed::from_slice(&raw_signing_key_seed).ok_or_else(|| anyhow!("Cannot parse seed"))?;
    let (_, signing_key) = keypair_from_seed(&signing_key_seed);

    pack(
        &container_src_dir,
        &out_dir,
        &signing_key,
        fs_type,
        uid,
        gid,
    )?;

    Ok(())
}

fn pack(
    src_dir: &Path,
    out_dir: &Path,
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
    debug!("out_dir={}", out_dir.display());

    // load manifest
    let manifest_file_path = src_dir.join("manifest").with_extension("yaml");
    let arch = "x86_64-unknown-linux-gnu"; // TODO: get as CLI parameter
    let manifest_file = std::fs::File::open(&manifest_file_path)
        .with_context(|| format!("Could not open manifest {}", manifest_file_path.display()))?;
    debug!("read manifest file {}", manifest_file_path.display());
    let manifest: Manifest = serde_yaml::from_reader(manifest_file)
        .with_context(|| format!("Failed to parse {}", manifest_file_path.display()))?;

    let tmp_dir =
        TempDir::new("").with_context(|| "Could not create temporary directory".to_string())?;

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
            .with_context(|| "Could not create temporary directory".to_string())?;
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
        unimplemented!("For unknown file types")
    }
    debug!("fsimg_path={}", fsimg_path.as_os_str().to_str().unwrap());
    let filesystem_size = fs::metadata(fsimg_path)?.len();

    // append verity header and hash tree to filesystem image
    assert_eq!(filesystem_size % BLOCK_SIZE, 0);
    let data_blocks: u64 = filesystem_size / BLOCK_SIZE;
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
    debug!("data_blocks={}", &data_blocks);
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

    let (verity_hash, hash_tree) = generate_hash_tree(
        &File::open(&fsimg_path)?,
        filesystem_size,
        BLOCK_SIZE,
        &salt,
        &hash_level_offsets,
        tree_size,
    )?;
    debug!("verity_hash.len()={}", verity_hash.len());
    debug!("hash_tree.len()={}", hash_tree.len());

    {
        /* ['verity', 1, 1, uuid.gsub('-', ''), 'sha256', 4096, 4096, data_blocks, 32, salt, '']
         * .pack('a8 L L H32 a32 L L Q S x6 a256 a3752')
         * (https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format)
         * (https://ruby-doc.org/core-2.7.1/Array.html#method-i-pack) */
        let mut fsimg = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&fsimg_path)?;
        // File::open(&fsimg_path)?;
        // fsimg.seek(Start(filesystem_size));
        // fsimg.seek(End(0));
        fsimg.write_all(b"verity")?;
        fsimg.write_all(&[0_u8, 0_u8])?;
        fsimg.write_all(&1_u32.to_ne_bytes())?;
        fsimg.write_all(&1_u32.to_ne_bytes())?;
        fsimg.write_all(&hex::decode(uuid.to_string().replace("-", ""))?)?;
        fsimg.write_all(b"sha256")?;
        fsimg.write_all(&[0_u8; 26])?;
        fsimg.write_all(&4096_u32.to_ne_bytes())?;
        fsimg.write_all(&4096_u32.to_ne_bytes())?;
        fsimg.write_all(&data_blocks.to_ne_bytes())?;
        fsimg.write_all(&32_u16.to_ne_bytes())?;
        fsimg.write_all(&[0_u8; 6])?;
        fsimg.write_all(&salt)?;
        fsimg.write_all(&vec![0_u8; 256 - salt.len()])?;
        fsimg.write_all(&[0_u8; 3752])?;
        fsimg.write_all(&hash_tree)?;
    }

    // create hashes YAML
    let mut sha256 = Sha256::new();
    io::copy(&mut File::open(&tmp_manifest_dir)?, &mut sha256)?;
    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    let mut fsimg = File::open(&fsimg_path)?;
    // fsimg.seek(Start(0)); // return to start of file before hashing
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
    let path_to_npk = out_dir
        .join(format!("{}-{}-{}.", manifest.name, arch, manifest.version))
        .with_extension("npk");
    debug!("path_to_npk=\n{}", &path_to_npk.display());
    let npk_file = File::create(&path_to_npk)?;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(&npk_file);
    zip.start_file("signature.yaml", options)?;
    zip.write_all(signatures.as_bytes())?;
    zip.start_file("manifest.yaml", options)?;
    let manifest_string = serde_yaml::to_string(&manifest)?;
    zip.write_all(manifest_string.as_bytes())?;

    let offset = 43 + manifest_string.len() + 44 + signatures.len() + 36; // stored
    let padding = (offset / 4096 + 1) * 4096 - offset;

    let zeros = vec![0_u8; padding as usize];

    zip.start_file_with_extra_data("fs.img", options, &zeros)?;
    let mut fsimg = File::open(&fsimg_path)?;
    let mut fsimg_cont: Vec<u8> = vec![0u8; fs::metadata(&fsimg_path).unwrap().len() as usize];
    fsimg.read_exact(&mut fsimg_cont)?;
    zip.write_all(&fsimg_cont)?;

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
        num_levels += 1;

        size = level_size;
    }

    for n in 0..num_levels {
        let mut offset = 0;
        #[allow(clippy::needless_range_loop)]
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
    hash_level_offsets: &[usize],
    tree_size: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
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
                reader.seek(Start(offset))?;
                reader.read_exact(&mut data)?;
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

            remaining -= data_len;
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
            round_up_to_multiple(level_output.len(), block_size as usize) - level_output.len();
        level_output.append(&mut vec![0_u8; padding_needed]);

        let offset = hash_level_offsets[level_num];
        hash_ret[offset..offset + level_output.len()].copy_from_slice(level_output.as_slice());

        hash_src_size = level_output.len() as u64;
        level_num += 1;
    }

    let digest = Sha256::digest(
        &salt
            .iter()
            .copied()
            .chain(level_output.iter().copied())
            .collect::<Vec<u8>>(),
    );

    Ok((digest.to_vec(), hash_ret))
}

fn round_up_to_multiple(number: usize, factor: usize) -> usize {
    let round_down_to_multiple = number + factor - 1;
    round_down_to_multiple - (round_down_to_multiple % factor)
}
