#!/bin/bash
set -e

pkgs=("./engine" "./reducer")

tmp=$(mktemp -d)
coverprofile="${tmp}/coverage.out"
coverage_dir=".github/coverage"
tmp_out="${tmp}/coverage.txt"
out="${coverage_dir}/coverage.txt"
commit=$(git rev-parse HEAD)


GOOS=linux go test -short -failfast -coverprofile="${coverprofile}" ${pkgs[*]}
go tool cover -func "${coverprofile}" | tee "${tmp_out}"

mkdir -p "${coverage_dir}"
cp ${tmp_out} ${out}

url_message=`cat ${out} | tail -n -1 | awk -F"\t" '{print $NF}' | tr -d '[:cntrl:]' | sed 's/%/%25/'`
curl -s https://img.shields.io/badge/coverage-${url_message}-informational?style=for-the-badge > ${coverage_dir}/badge.svg