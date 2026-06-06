#!/usr/bin/env bash
set -euo pipefail
IMG="${1:-$(dirname "$0")/../assets/test1.img}"

hash_one() {
  local path="$1"
  local bytes hash
  bytes=$(mcopy -i "$IMG" "$path" - | wc -c | tr -d ' ')
  hash=$(mcopy -i "$IMG" "$path" - | sha256sum | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$path" "$bytes" "$hash"
}

hash_one ::/lorem_ipsum.txt
hash_one ::/books/english/macbeth.txt
hash_one ::/books/polish/pan-tadeusz.txt
hash_one "::/fruits/random things/random2/Methamphetamine.txt"
hash_one "::/fruits/random things/random2/Till Lindemann.txt"
