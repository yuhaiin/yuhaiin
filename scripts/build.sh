c_dir=$(dirname "$(readlink -f "$0")")
# shellcheck disable=SC2164
cd "${c_dir}/.."
go build -v "${c_dir}/../cmd/..."