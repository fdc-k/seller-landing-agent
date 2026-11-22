#!/bin/sh
# Public entry contains no enrollment capability or Seller credential.
set -eu
umask 077
[ "$#" -eq 2 ] || { printf '%s\n' 'Trusted origin and bootstrap SHA256 are required' >&2; exit 1; }
expected_origin="$1"; expected_sha="$2"
case "$expected_origin" in *[!A-Za-z0-9.:/-]*) exit 1;; esac
case "$expected_sha" in *[!a-f0-9]*) exit 1;; esac
printf '%s' "$expected_origin" | /usr/bin/grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' || exit 1
printf '%s' "$expected_sha" | /usr/bin/grep -Eq '^[a-f0-9]{64}$' || exit 1
url=''; file=''; tty_state=''
cleanup(){ [ -z "$tty_state" ] || stty "$tty_state" </dev/tty; [ -z "$file" ] || /bin/rm -f "$file"; unset url; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
printf '%s' 'Paste your private account enrollment URL: ' >/dev/tty
tty_state=$(stty -g </dev/tty); stty -echo </dev/tty
IFS= read -r url </dev/tty
stty "$tty_state" </dev/tty; tty_state=''; printf '\n' >/dev/tty
case "$url" in "$expected_origin"/api/seller-center/landing/bootstrap/*) ticket=${url#"$expected_origin"/api/seller-center/landing/bootstrap/};; *) printf '%s\n' 'Private enrollment URL does not match trusted origin' >&2; exit 1;; esac
case "$ticket" in */windows.ps1) ticket=${ticket%/windows.ps1};; */macos.sh) ticket=${ticket%/macos.sh};; esac
printf '%s' "$ticket" | /usr/bin/grep -Eq '^[A-Za-z0-9_-]{43}$' || exit 1
url="$expected_origin/api/seller-center/landing/bootstrap/$ticket/macos.sh"
file=$(/usr/bin/mktemp)
# Send the capability through stdin instead of exposing it in curl arguments.
printf 'url = "%s"\n' "$url" | /usr/bin/curl --config - --fail --silent --show-error --proto '=https' --tlsv1.2 --max-redirs 0 --max-time 180 --output "$file"
unset url ticket
actual_sha=$(/usr/bin/shasum -a 256 "$file" | /usr/bin/awk '{print $1}')
[ "$actual_sha" = "$expected_sha" ] || { printf '%s\n' 'Bootstrap integrity mismatch' >&2; exit 1; }
/bin/sh "$file"
