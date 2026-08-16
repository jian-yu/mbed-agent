#!/bin/sh
set -eu

usage() {
    echo "usage: $0 SOURCE_DIR DEST_DIR" >&2
    exit 2
}

[ "$#" = 2 ] || usage
source_dir=$1
dest_dir=$2
test -d "$source_dir"
mkdir -p "$dest_dir"

# Keep the relative layout and entry types so the write-set checker can detect
# additions, deletions, empty directories, and symlink target changes without
# copying anything back to persistent storage.
find "$source_dir" -mindepth 1 -type d -print | while IFS= read -r path; do
    relative=${path#"$source_dir"/}
    mkdir -p "$dest_dir/$relative"
done
find "$source_dir" -mindepth 1 -type f -print | while IFS= read -r path; do
    relative=${path#"$source_dir"/}
    mkdir -p "$dest_dir/$(dirname "$relative")"
    cp -p "$path" "$dest_dir/$relative"
done
find "$source_dir" -mindepth 1 -type l -print | while IFS= read -r path; do
    relative=${path#"$source_dir"/}
    mkdir -p "$dest_dir/$(dirname "$relative")"
    ln -s "$(readlink "$path")" "$dest_dir/$relative"
done
