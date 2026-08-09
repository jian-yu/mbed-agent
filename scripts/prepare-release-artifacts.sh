#!/bin/sh
set -eu

usage() {
    echo "usage: $0 BINARY [OUTPUT_DIR]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage
binary=$1
output_dir=${2:-dist/release}
test -f "$binary"
command -v sha256sum >/dev/null 2>&1
command -v cargo >/dev/null 2>&1
command -v rustc >/dev/null 2>&1

version=$($binary --version | awk 'NR == 1 { print $2; exit }')
case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "could not determine a semantic version from $binary --version" >&2
        exit 1
        ;;
esac

mkdir -p "$output_dir"
artifact="$output_dir/mbed-agent-$version"
cp "$binary" "$artifact"

size=$(stat -f '%z' "$artifact" 2>/dev/null || stat -c '%s' "$artifact")
binary_sha256=$(sha256sum "$artifact" | awk '{print $1}')
git_revision=unknown
if command -v git >/dev/null 2>&1; then
    git_revision=$(git rev-parse HEAD 2>/dev/null || printf '%s' unknown)
fi

# Keep the raw Cargo graph separate. A release service can convert it into
# SPDX/CycloneDX without adding another generator to the embedded build.
metadata_platform=${MBED_AGENT_METADATA_PLATFORM:-}
if [ -n "$metadata_platform" ]; then
    cargo metadata --locked --filter-platform "$metadata_platform" --format-version 1 \
        > "$output_dir/sbom.cargo.json"
    cargo tree --locked --target "$metadata_platform" --prefix none \
        > "$output_dir/cargo-tree.txt"
else
    cargo metadata --locked --format-version 1 > "$output_dir/sbom.cargo.json"
    cargo tree --locked --prefix none > "$output_dir/cargo-tree.txt"
fi
rustc -Vv > "$output_dir/rustc-version.txt"

cat > "$output_dir/manifest.json" <<EOF
{
  "schema": "mbed-agent-release-manifest-1",
  "version": "$version",
  "binary": "$(basename "$artifact")",
  "binary_sha256": "$binary_sha256",
  "binary_size_bytes": $size,
  "git_revision": "$git_revision",
  "dependency_manifest": "sbom.cargo.json",
  "dependency_tree": "cargo-tree.txt",
  "toolchain": "rustc-version.txt"
}
EOF

(
    cd "$output_dir"
    find . -type f ! -name checksums.sha256 -print \
        | sed 's#^./##' \
        | sort \
        | xargs sha256sum
) > "$output_dir/checksums.sha256"

(cd "$output_dir" && sha256sum -c checksums.sha256 >/dev/null)

echo "PASS: release artifacts created at $output_dir (version $version)"
