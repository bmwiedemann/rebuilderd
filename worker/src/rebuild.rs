use crate::config;
use crate::diffoscope::diffoscope;
use crate::download::download;
use crate::heartbeat::HeartBeat;
use crate::log;
use crate::proc;
use in_toto::crypto::PrivateKey;
use in_toto::runlib::in_toto_run;
use rebuilderd_common::api::v1::{ArtifactStatus, QueuedJobArtifact, RebuildArtifactReport};
use rebuilderd_common::errors::Context as _;
use rebuilderd_common::errors::*;
use rebuilderd_common::utils::zstd_compress;
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, SeekFrom};
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time;

pub struct Context<'a> {
    pub artifacts: Vec<QueuedJobArtifact>,
    pub input_url: Option<String>,
    pub backend: config::Backend,
    pub build: config::Build,
    pub diffoscope: config::Diffoscope,
    pub privkey: &'a PrivateKey,
}

fn path_to_string(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .with_context(|| anyhow!("Path contains invalid characters: {:?}", path))?;
    Ok(s.to_string())
}

const RPM_LEAD_MAGIC: &[u8] = b"\xed\xab\xee\xdb";
const RPM_HEADER_MAGIC: &[u8] = b"\x8e\xad\xe8";
const RPM_LEAD_SIZE: usize = 96;
const RPM_HEADER_INTRO_SIZE: usize = 16;

/// Distributions sign their rpms after building them, which a rebuild can not
/// reproduce. The signature lives in a header of its own in front of the
/// package, so return the offset just past it to compare the rest.
///
/// Returns 0 for everything that isn't an rpm.
fn rpm_body_offset(buf: &[u8]) -> u64 {
    let Some(header) = buf.strip_prefix(RPM_LEAD_MAGIC) else {
        return 0;
    };
    let Some(header) = header
        .get(RPM_LEAD_SIZE - RPM_LEAD_MAGIC.len()..)
        .and_then(|h| h.strip_prefix(RPM_HEADER_MAGIC))
    else {
        return 0;
    };

    // the intro is the magic, a version byte, 4 reserved bytes, the number of
    // index entries and the size of the data they point into
    let Some(intro) = header.get(5..13) else {
        return 0;
    };
    let index_entries = u32::from_be_bytes(intro[..4].try_into().unwrap()) as u64;
    let data_size = u32::from_be_bytes(intro[4..].try_into().unwrap()) as u64;

    let offset =
        RPM_LEAD_SIZE as u64 + RPM_HEADER_INTRO_SIZE as u64 + index_entries * 16 + data_size;
    // the header that follows is aligned to 8 bytes
    offset.next_multiple_of(8)
}

/// Read enough of the file to find where its signature header ends.
async fn skip_rpm_signature(f: &mut File, path: &Path) -> Result<u64> {
    let mut buf = [0u8; RPM_LEAD_SIZE + RPM_HEADER_INTRO_SIZE];
    let n = f.read(&mut buf).await?;
    let offset = rpm_body_offset(&buf[..n]);
    if offset > 0 {
        debug!("Skipping {offset} bytes of rpm signature header in {path:?}");
    }
    f.seek(SeekFrom::Start(offset)).await?;
    Ok(offset)
}

pub async fn compare_files(a: &Path, b: &Path) -> Result<bool> {
    let mut buf1 = [0u8; 4096];
    let mut buf2 = [0u8; 4096];

    info!("Comparing {:?} with {:?}", a, b);
    let mut f1 = File::open(a)
        .await
        .with_context(|| anyhow!("Failed to open {:?}", a))?;
    let mut f2 = File::open(b)
        .await
        .with_context(|| anyhow!("Failed to open {:?}", b))?;

    // the signature headers may have different sizes, so track the offsets apart
    let offset = skip_rpm_signature(&mut f1, a).await?;
    skip_rpm_signature(&mut f2, b).await?;

    let mut pos = offset as usize;
    loop {
        // read up to 4k bytes from the first file
        let n = f1.read_buf(&mut &mut buf1[..]).await?;

        // check if the first file is end-of-file
        if n == 0 {
            debug!("First file is at end-of-file");

            // check if other file is eof too
            let n = f2.read_buf(&mut &mut buf2[..]).await?;
            if n > 0 {
                info!("Files are not identical, {:?} is longer", b);
                return Ok(false);
            } else {
                return Ok(true);
            }
        }

        // check the same chunk in the other file
        match f2.read_exact(&mut buf2[..n]).await {
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                info!("Files are not identical, {:?} is shorter", b);
                return Ok(false);
            }
            err => err?,
        };

        if buf1[..n] != buf2[..n] {
            // get the exact position
            // this can't panic because we've already checked the slices are not equal
            let pos = pos
                + buf1[..n]
                    .iter()
                    .zip(buf2[..n].iter())
                    .position(|(a, b)| a != b)
                    .unwrap();
            info!("Files {:?} and {:?} differ at position {}", a, b, pos);

            return Ok(false);
        }

        // advance the number of bytes that are equal
        pos += n;
    }
}

pub async fn rebuild_with_heartbeat(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
    hb: &dyn HeartBeat,
) -> Result<Vec<RebuildArtifactReport>> {
    let mut rebuild = Box::pin(rebuild(ctx, log));
    loop {
        tokio::select! {
            res = &mut rebuild => {
                return res;
            },
            _ = time::sleep(hb.interval()) => hb.ping().await?,
        }
    }
}

pub async fn rebuild(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
) -> Result<Vec<RebuildArtifactReport>> {
    // setup
    let tmp = tempfile::Builder::new().prefix("rebuilderd").tempdir()?;

    let inputs_dir = tmp.path().join("inputs");
    fs::create_dir(&inputs_dir).context("Failed to create inputs/ temp dir")?;

    let out_dir = tmp.path().join("out");
    fs::create_dir(&out_dir).context("Failed to create out/ temp dir")?;

    // download
    let mut artifacts = Vec::new();
    for artifact in &ctx.artifacts {
        let artifact_filename = download(&artifact.url, &inputs_dir)
            .await
            .with_context(|| {
                anyhow!(
                    "Failed to download original package from {:?}",
                    artifact.url
                )
            })?;
        let artifact_path = inputs_dir.join(&artifact_filename);
        artifacts.push((artifact.clone(), artifact_filename, artifact_path));
    }

    let input_filename = if let Some(input_url) = &ctx.input_url {
        download(input_url, &inputs_dir)
            .await
            .with_context(|| anyhow!("Failed to download build input from {:?}", input_url))?
    } else {
        artifacts
            .first()
            .context("Failed to use first artifact as build input")?
            .1
            .to_owned()
    };
    let input_path = inputs_dir.join(&input_filename);

    // rebuild
    verify(ctx, log, &out_dir, &input_path).await?;

    // process results
    let mut results = Vec::new();
    for (artifact, artifact_filename, artifact_path) in artifacts {
        let output_path = out_dir.join(&artifact_filename);

        let result = if !output_path.exists() {
            info!(
                "No output artifact found, marking as BAD: {:?}",
                output_path
            );

            RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Bad,
            }
        } else if compare_files(&artifact_path, &output_path).await? {
            info!(
                "Output artifacts is identical, marking as GOOD: {:?}",
                output_path
            );

            let mut res = RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Good,
            };

            info!("Generating signed link");
            match in_toto_run(
                &format!("rebuild {}", artifact_filename.to_str().unwrap()),
                None,
                &[input_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Input path contains invalid characters"))?],
                &[output_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Output path contains invalid characters"))?],
                &[],
                Some(ctx.privkey),
                Some(&["sha512", "sha256"]),
                Some(&[
                    &format!("{}/", inputs_dir.to_str().unwrap()),
                    &format!("{}/", out_dir.to_str().unwrap()),
                ]),
            ) {
                Ok(signed_link) => {
                    info!("Signed link generated");

                    let attestation = serde_json::to_string(&signed_link)
                        .context("Failed to serialize attestation")?;

                    let encoded_attestation = zstd_compress(attestation.as_bytes())
                        .await
                        .map_err(Error::from)?;

                    res.attestation = Some(encoded_attestation);
                }
                Err(err) => warn!("Failed to generate in-toto attestation: {:#?}", err),
            }

            res
        } else {
            info!("Output artifact differs, marking as BAD: {:?}", output_path);

            let mut res = RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Bad,
            };

            // generate diffoscope diff if enabled
            if ctx.diffoscope.enabled {
                let diff = diffoscope(&artifact_path, &output_path, &ctx.diffoscope)
                    .await
                    .context("Failed to run diffoscope")?;

                let encoded_diffoscope =
                    zstd_compress(diff.as_bytes()).await.map_err(Error::from)?;

                res.diffoscope = Some(encoded_diffoscope);
            }

            res
        };

        results.push(result);
    }

    Ok(results)
}

async fn verify(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
    out_dir: &Path,
    input_path: &Path,
) -> Result<()> {
    let bin = &ctx.backend.path;
    let timeout = ctx.build.timeout.unwrap_or(3600 * 24); // 24h

    let mut envs = HashMap::new();
    envs.insert("REBUILDERD_OUTDIR".into(), path_to_string(out_dir)?);

    let opts = proc::Options {
        timeout: Duration::from_secs(timeout),
        kill_at_size_limit: false,
        passthrough: !ctx.build.silent,
        envs,
    };

    proc::run(bin.as_ref(), &[input_path], opts, log).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compare_files_equal() {
        let equal = compare_files(Path::new("src/main.rs"), Path::new("src/main.rs"))
            .await
            .unwrap();
        assert!(equal);
    }

    #[tokio::test]
    async fn compare_files_not_equal1() {
        let equal = compare_files(Path::new("src/main.rs"), Path::new("Cargo.toml"))
            .await
            .unwrap();
        assert!(!equal);
    }

    #[tokio::test]
    async fn compare_files_not_equal2() {
        let equal = compare_files(Path::new("Cargo.toml"), Path::new("src/main.rs"))
            .await
            .unwrap();
        assert!(!equal);
    }

    #[tokio::test]
    async fn compare_large_files_equal() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), [0u8; 4096 * 100]).unwrap();
        fs::write(dir.path().join("b"), [0u8; 4096 * 100]).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(equal);
    }

    #[tokio::test]
    async fn compare_large_files_not_equal() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), [0u8; 4096 * 100]).unwrap();
        fs::write(dir.path().join("b"), [1u8; 4096 * 100]).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(!equal);
    }

    /// An rpm with a signature header of `sig_entries` entries pointing into
    /// `sig_data`, followed by `body`.
    fn fake_rpm(sig_entries: u32, sig_data: &[u8], body: &[u8]) -> Vec<u8> {
        let mut rpm = Vec::new();
        rpm.extend_from_slice(RPM_LEAD_MAGIC);
        rpm.resize(RPM_LEAD_SIZE, 0);

        rpm.extend_from_slice(RPM_HEADER_MAGIC);
        rpm.extend_from_slice(&[0x01, 0, 0, 0, 0]);
        rpm.extend_from_slice(&sig_entries.to_be_bytes());
        rpm.extend_from_slice(&(sig_data.len() as u32).to_be_bytes());
        rpm.resize(rpm.len() + sig_entries as usize * 16, 0);
        rpm.extend_from_slice(sig_data);
        rpm.resize(rpm.len().next_multiple_of(8), 0);

        rpm.extend_from_slice(body);
        rpm
    }

    #[test]
    fn rpm_body_offset_of_non_rpm() {
        assert_eq!(rpm_body_offset(b""), 0);
        assert_eq!(rpm_body_offset(b"ohai"), 0);
        // a truncated lead
        assert_eq!(rpm_body_offset(b"\xed\xab\xee\xdb"), 0);
    }

    #[test]
    fn rpm_body_offset_skips_signature_header() {
        let rpm = fake_rpm(2, b"some signature", b"payload");
        // 96 lead + 16 intro + 2 index entries + 14 bytes of data, padded to 8
        assert_eq!(rpm_body_offset(&rpm), 160);
        assert_eq!(&rpm[160..], b"payload");
    }

    #[tokio::test]
    async fn compare_rpms_differing_only_in_signature() {
        let dir = tempfile::tempdir().unwrap();
        // a signed package carries more signature tags than the rebuild of it
        fs::write(
            dir.path().join("a"),
            fake_rpm(3, b"signed by the distro", b"identical body"),
        )
        .unwrap();
        fs::write(dir.path().join("b"), fake_rpm(1, b"", b"identical body")).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(equal);
    }

    #[tokio::test]
    async fn compare_rpms_differing_in_body() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), fake_rpm(3, b"signature", b"one body")).unwrap();
        fs::write(dir.path().join("b"), fake_rpm(1, b"", b"other body")).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(!equal);
    }
}
