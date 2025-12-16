set -e
export CC="zig cc -target x86_64-linux-gnu.2.17"
go build
set -a
source .env
set +a
./tvsuggest