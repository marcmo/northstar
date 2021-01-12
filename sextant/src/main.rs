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

use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

mod inspect;

#[derive(Debug, StructOpt)]
#[structopt(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        /// Key file
        #[structopt(short, long)]
        key: PathBuf,
        /// Output directory
        #[structopt(short, long)]
        out: PathBuf,
        /// Compression algorithm to use in squashfs (default gzip)
        #[structopt(short, long)]
        comp: Option<npk::npk::CompAlg>,
        /// Block size used by squashfs (default 128 KiB)
        #[structopt(short, long)]
        block_size: Option<u32>,
    },
    /// Unpack Northstar containers
    Unpack {
        /// NPK path
        #[structopt(short, long)]
        npk: PathBuf,
        /// Output directory
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        #[structopt(short, long)]
        short: bool,
        /// NPK to inspect
        npk: PathBuf,
    },
    GenKey {
        /// Name of key
        #[structopt(short, long)]
        name: String,
        /// Key directory
        #[structopt(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Opt::from_args() {
        Opt::Pack {
            dir,
            out,
            key,
            comp,
            block_size,
        } => {
            let mut squashfs_opts = npk::npk::SquashfsOpts::default();
            if let Some(compression_alg) = comp {
                squashfs_opts.comp = compression_alg;
            }
            if let Some(size) = block_size {
                squashfs_opts.block_size = size;
            }
            npk::npk::pack_with(&dir, &out, Some(key.as_path()), squashfs_opts)?
        }
        Opt::Unpack { npk, out } => npk::npk::unpack(&npk, &out)?,
        Opt::Inspect { npk, short } => inspect::inspect(&npk, short)?,
        Opt::GenKey { name, out } => npk::npk::gen_key(&name, &out)?,
    }
    Ok(())
}
