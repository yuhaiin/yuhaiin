c_dir=$(dirname "$(readlink -f "$0")")
# shellcheck disable=SC2164
cd "${c_dir}/../cmd/yuhaiin"
go build -v