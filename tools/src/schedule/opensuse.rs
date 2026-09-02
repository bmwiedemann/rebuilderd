use crate::args::PkgsSync;
use crate::config::SyncRelease;
use crate::rules;
use crate::schedule::repomd::{self, PackagesXmlItem};
use rebuilderd_common::api::v1::{BinaryPackageReport, PackageReport, SourcePackageReport};
use rebuilderd_common::errors::*;
use rebuilderd_common::http;
use std::collections::BTreeMap;

const DISTRIBUTION: &str = "opensuse";

/// Join a repodata location onto the base url. openSUSE's per-architecture
/// indexes point back out of their directory with `../`.
fn join_url(base_url: &str, href: &str) -> String {
    let mut base = base_url;
    let mut href = href;
    while let Some(rest) = href.strip_prefix("../") {
        base = base.rsplit_once('/').map_or(base, |(parent, _)| parent);
        href = rest;
    }
    format!("{base}/{href}")
}

/// Collects packages into one report per (release, architecture).
#[derive(Debug, Default)]
struct SyncState {
    reports: BTreeMap<(String, String), BTreeMap<String, SourcePackageReport>>,
}

impl SyncState {
    /// Report a scope even when nothing matched, so the daemon can expire
    /// packages that disappeared from the index.
    fn create_group(&mut self, release: &str, architecture: &str) {
        self.reports
            .entry((release.to_string(), architecture.to_string()))
            .or_default();
    }

    fn push(
        &mut self,
        release: &str,
        architecture: &str,
        base_url: &str,
        component: &str,
        pkg: &PackagesXmlItem,
    ) {
        let url = join_url(base_url, &pkg.location.href);
        let version = format!("{}-{}", pkg.version.ver, pkg.version.rel);

        let group = self
            .reports
            .entry((release.to_string(), architecture.to_string()))
            .or_default()
            .entry(pkg.format.sourcerpm.clone())
            .or_insert_with(|| SourcePackageReport {
                name: pkg.format.sourcerpm.clone(),
                version: version.clone(),
                url: url.clone(),
                artifacts: Vec::new(),
            });

        // the rebuilder reads the build target off this rpm, so prefer one that
        // names an architecture over a noarch subpackage
        if pkg.arch == architecture
            && !group
                .artifacts
                .iter()
                .any(|artifact| artifact.architecture == architecture)
        {
            group.url = url.clone();
        }

        group.artifacts.push(BinaryPackageReport {
            name: pkg.name.clone(),
            version,
            component: Some(component.to_string()),
            architecture: pkg.arch.clone(),
            url,
        });
    }

    fn import_packages(
        &mut self,
        packages: Vec<PackagesXmlItem>,
        base_url: &str,
        release: &SyncRelease,
        component: &str,
        sync: &PkgsSync,
    ) {
        for pkg in packages {
            if !rules::matches(sync, &pkg, component) {
                continue;
            }

            // one index covers every architecture, and noarch subpackages belong
            // to all of them because a rebuild verifies every artifact of a
            // source package at once
            for arch in &sync.architectures {
                if pkg.arch == *arch || pkg.arch == "noarch" {
                    self.push(release.name(), arch, base_url, component, &pkg);
                }
            }
        }
    }

    fn into_vec(self) -> Vec<PackageReport> {
        self.reports
            .into_iter()
            .map(|((release, architecture), groups)| PackageReport {
                distribution: DISTRIBUTION.to_string(),
                release: Some(release),
                architecture,
                packages: groups.into_values().collect(),
            })
            .collect()
    }
}

pub async fn sync(http: &http::Client, sync: &PkgsSync) -> Result<Vec<PackageReport>> {
    let mut state = SyncState::default();

    for release in &sync.releases {
        for arch in &sync.architectures {
            state.create_group(release.name(), arch);
        }

        for component in &sync.components {
            // the release is part of `source`, eg https://download.opensuse.org/tumbleweed/repo
            let base_url = format!("{}/{}", release.source(&sync.source), component);
            info!("Syncing openSUSE {:?} from {:?}", release.name(), base_url);

            let packages = repomd::fetch_package_index(http, &base_url).await?;
            state.import_packages(packages, &base_url, release, component, sync);
        }
    }

    Ok(state.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAP_SOURCE: &str = "https://download.opensuse.org/distribution/leap/16.0/repo";

    /// The `hello` source package of Leap 16.0: one binary per architecture plus
    /// a noarch subpackage.
    const HELLO: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="5">
<package type="rpm">
  <name>hello</name>
  <arch>aarch64</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <checksum type="sha512" pkgid="YES">deadbeef</checksum>
  <summary>A Friendly Greeting Program</summary>
  <packager>https://bugs.opensuse.org</packager>
  <location href="aarch64/hello-2.12.1-bp160.1.13.aarch64.rpm"/>
  <format>
    <rpm:vendor>openSUSE</rpm:vendor>
    <rpm:buildhost>reproducible</rpm:buildhost>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>hello</name>
  <arch>ppc64le</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="ppc64le/hello-2.12.1-bp160.1.13.ppc64le.rpm"/>
  <format>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>hello</name>
  <arch>s390x</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="s390x/hello-2.12.1-bp160.1.13.s390x.rpm"/>
  <format>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>hello</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="x86_64/hello-2.12.1-bp160.1.13.x86_64.rpm"/>
  <format>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>hello-lang</name>
  <arch>noarch</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="noarch/hello-lang-2.12.1-bp160.1.13.noarch.rpm"/>
  <format>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
</metadata>
"#;

    /// A source package whose noarch subpackage sorts before its native one.
    const NOARCH_FIRST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
<package type="rpm">
  <name>aaa-doc</name>
  <arch>noarch</arch>
  <version epoch="0" ver="1.0" rel="1.1"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="noarch/aaa-doc-1.0-1.1.noarch.rpm"/>
  <format>
    <rpm:sourcerpm>aaa-1.0-1.1.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>aaa-tools</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1.1"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="x86_64/aaa-tools-1.0-1.1.x86_64.rpm"/>
  <format>
    <rpm:sourcerpm>aaa-1.0-1.1.src.rpm</rpm:sourcerpm>
  </format>
</package>
</metadata>
"#;

    fn gen_sync(architectures: &[&str]) -> PkgsSync {
        PkgsSync {
            distro: "opensuse".to_string(),
            sync_method: None,
            components: vec!["oss".to_string()],
            releases: vec![SyncRelease::new("leap-16.0")],
            architectures: architectures.iter().map(|a| a.to_string()).collect(),
            source: LEAP_SOURCE.to_string(),
            print_json: false,
            include: Vec::new(),
            maintainers: Vec::new(),
            pkgs: Vec::new(),
            excludes: Vec::new(),
        }
    }

    fn import(index: &[u8], architectures: &[&str]) -> Result<Vec<PackageReport>> {
        let sync = gen_sync(architectures);
        let base_url = format!("{LEAP_SOURCE}/oss");
        let packages = repomd::parse_package_index(index)?;

        let mut state = SyncState::default();
        for arch in &sync.architectures {
            state.create_group(sync.releases[0].name(), arch);
        }
        state.import_packages(packages, &base_url, &sync.releases[0], "oss", &sync);
        Ok(state.into_vec())
    }

    #[test]
    fn test_join_url() {
        assert_eq!(
            join_url("https://example.com/repo/oss", "x86_64/hello.rpm"),
            "https://example.com/repo/oss/x86_64/hello.rpm"
        );
        // the per-architecture indexes of Leap point back out of their directory
        assert_eq!(
            join_url("https://example.com/repo/oss/x86_64", "../noarch/hello.rpm"),
            "https://example.com/repo/oss/noarch/hello.rpm"
        );
    }

    #[test]
    fn test_noarch_merged_into_every_architecture() -> Result<()> {
        let reports = import(HELLO, &["x86_64", "aarch64"])?;
        assert_eq!(reports.len(), 2);

        for (report, arch) in reports.iter().zip(["aarch64", "x86_64"]) {
            assert_eq!(report.distribution, "opensuse");
            assert_eq!(report.release.as_deref(), Some("leap-16.0"));
            assert_eq!(report.architecture, arch);
            assert_eq!(report.packages.len(), 1);

            let group = &report.packages[0];
            assert_eq!(group.name, "hello-2.12.1-bp160.1.13.src.rpm");
            assert_eq!(group.version, "2.12.1-bp160.1.13");

            // the native binary plus the shared noarch subpackage
            let artifacts = group
                .artifacts
                .iter()
                .map(|a| (a.name.as_str(), a.architecture.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(artifacts, &[("hello", arch), ("hello-lang", "noarch")]);
        }

        Ok(())
    }

    #[test]
    fn test_foreign_architectures_are_dropped() -> Result<()> {
        let reports = import(HELLO, &["x86_64"])?;
        assert_eq!(reports.len(), 1);

        let architectures = reports[0].packages[0]
            .artifacts
            .iter()
            .map(|a| a.architecture.as_str())
            .collect::<Vec<_>>();
        assert_eq!(architectures, &["x86_64", "noarch"]);

        Ok(())
    }

    #[test]
    fn test_build_input_url_prefers_native_arch() -> Result<()> {
        let reports = import(NOARCH_FIRST, &["x86_64"])?;
        let group = &reports[0].packages[0];

        assert_eq!(
            group.url,
            format!("{LEAP_SOURCE}/oss/x86_64/aaa-tools-1.0-1.1.x86_64.rpm")
        );
        assert_eq!(group.artifacts.len(), 2);

        Ok(())
    }

    #[test]
    fn test_artifact_urls_and_component() -> Result<()> {
        let reports = import(HELLO, &["x86_64"])?;
        let artifacts = &reports[0].packages[0].artifacts;

        assert_eq!(
            artifacts[0].url,
            format!("{LEAP_SOURCE}/oss/x86_64/hello-2.12.1-bp160.1.13.x86_64.rpm")
        );
        assert_eq!(
            artifacts[1].url,
            format!("{LEAP_SOURCE}/oss/noarch/hello-lang-2.12.1-bp160.1.13.noarch.rpm")
        );
        for artifact in artifacts {
            assert_eq!(artifact.component.as_deref(), Some("oss"));
        }

        Ok(())
    }

    #[test]
    fn test_empty_release_group_is_reported() -> Result<()> {
        let index = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="0">
</metadata>
"#;
        let reports = import(index, &["x86_64"])?;
        assert_eq!(
            reports,
            &[PackageReport {
                distribution: "opensuse".to_string(),
                release: Some("leap-16.0".to_string()),
                architecture: "x86_64".to_string(),
                packages: Vec::new(),
            }]
        );

        Ok(())
    }

    #[test]
    fn test_maintainer_filter_skips_sle_packages() -> Result<()> {
        // Leap packages inherited from SLE are built on the internal
        // build.suse.de and can only be told apart by their packager
        let index = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
<package type="rpm">
  <name>bash</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="5.2.37" rel="160000.2.2"/>
  <packager>https://www.suse.com/</packager>
  <location href="x86_64/bash-5.2.37-160000.2.2.x86_64.rpm"/>
  <format>
    <rpm:sourcerpm>bash-5.2.37-160000.2.2.src.rpm</rpm:sourcerpm>
  </format>
</package>
<package type="rpm">
  <name>hello</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="2.12.1" rel="bp160.1.13"/>
  <packager>https://bugs.opensuse.org</packager>
  <location href="x86_64/hello-2.12.1-bp160.1.13.x86_64.rpm"/>
  <format>
    <rpm:sourcerpm>hello-2.12.1-bp160.1.13.src.rpm</rpm:sourcerpm>
  </format>
</package>
</metadata>
"#;
        let mut sync = gen_sync(&["x86_64"]);
        sync.maintainers = vec!["https://bugs.opensuse.org".to_string()];

        let base_url = format!("{LEAP_SOURCE}/oss");
        let packages = repomd::parse_package_index(&index[..])?;
        let mut state = SyncState::default();
        state.create_group("leap-16.0", "x86_64");
        state.import_packages(packages, &base_url, &sync.releases[0], "oss", &sync);
        let reports = state.into_vec();

        let names = reports[0]
            .packages
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, &["hello-2.12.1-bp160.1.13.src.rpm"]);

        Ok(())
    }
}
