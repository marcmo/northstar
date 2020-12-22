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

use color_eyre::eyre::{eyre, Result};
use north_tests::{
    logger,
    runtime::Runtime,
    test,
    test_container::{get_test_container_npk, get_test_resource_npk},
};
use std::{path::Path, time::Duration};
use tokio::fs;

test!(hello, {
    let mut runtime = Runtime::launch().await.unwrap();
    let hello = runtime.start("hello").await?;
    let hello = hello.ok_or_else(|| eyre!("Failed to get hello's PID"))?;

    // Here goes some kind of health check for the spawned process
    assert!(hello.is_running().await?);

    runtime.stop("hello").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(cpueater, {
    let mut runtime = Runtime::launch().await.unwrap();
    let cpueater = runtime.start("cpueater").await?;
    let cpueater = cpueater.ok_or_else(|| eyre!("Failed to get cpueater's PID"))?;

    assert!(cpueater.is_running().await?);
    assert_eq!(cpueater.get_cpu_shares().await?, 100);

    runtime.stop("cpueater").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(memeater, {
    let mut runtime = Runtime::launch().await.unwrap();
    let memeater = runtime.start("memeater").await?;
    let memeater = memeater.ok_or_else(|| eyre!("Failed to get memeater's PID"))?;

    assert!(memeater.is_running().await?);

    // NOTE
    // The limit in bytes indicated in the memory cgroup wont necessary be equal to the one
    // requested exactly. The kernel will assign some value close to it. For this reason we check
    // here that the limit assigned is greater than zero.
    assert!(memeater.get_limit_in_bytes().await? > 0);

    runtime.stop("memeater").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(data_and_resource_mounts, {
    let mut runtime = Runtime::launch().await.unwrap();

    // install test container & resource
    runtime.install("examples", get_test_resource_npk()).await?;
    runtime
        .install("examples", get_test_container_npk())
        .await?;

    let data_dir = Path::new("target/north/data/test_container-000");
    fs::create_dir_all(&data_dir).await?;

    let input_file = data_dir.join("input.txt");

    // Write the input to the test_container
    fs::write(&input_file, b"cat /resource/hello").await?;

    // // Start the test_container process
    runtime.start("test_container-000").await.map(drop)?;

    logger::assume("hello from test resource", Duration::from_secs(5)).await?;

    runtime.stop("test_container-000").await?;

    // Remove the temporary data directory
    fs::remove_dir_all(&data_dir).await?;

    runtime.uninstall("test_container", "0.0.1").await?;
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await?;
    Ok(())
});

test!(crashing_containers, {
    let mut runtime = Runtime::launch().await.unwrap();

    let data_dir = Path::new("target/north/data/").canonicalize()?;

    // install test container
    runtime.install("examples", get_test_resource_npk()).await?;
    runtime
        .install("examples", get_test_container_npk())
        .await?;

    for i in 0..5 {
        let dir = data_dir.join(format!("test_container-{:03}", i));
        fs::create_dir_all(&dir).await?;
        fs::write(dir.join("input.txt"), b"crash").await?;

        // Start the test_container process
        runtime
            .start(&format!("test_container-{:03}", i))
            .await
            .map(drop)?;
    }

    // Try to stop the containers before issuing the shutdown
    for i in 0..5 {
        runtime.stop(&format!("test_container-{:03}", i)).await?;
    }

    runtime.uninstall("test_container", "0.0.1").await?;
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await
});
