#!/bin/bash
#shell for building the project.
#param1: build_type

os=$(uname -o)
current_dir=$(dirname $0)

[[ $os =~ Msys ]] && platform=_WINDOWS || platform=_GNU
[[ $1 =~ [dD]ebug ]] && build_type=Debug || build_type=Release

for param in "${@:2}"; do
    generate_options="$generate_options \"$param\""
done
[[ $platform = _WINDOWS ]] && build_options="-- -v:n" || build_options="-- -j $(nproc)"

echo "building..."
echo "platform: $platform"
echo "build_type: $build_type"

include_dir=$current_dir/include
src_dir=$current_dir/src
tmp_dir=$current_dir/tmp
bin_dir=$current_dir/bin

[[ -d $include_dir ]] && rm -rf $include_dir/* || mkdir -p $include_dir
cp -f $src_dir/nids.h $include_dir
if [[ $platform = _WINDOWS ]]; then
    cp -rf $src_dir/_WINDOWS/netinet $include_dir
    cp -rf $current_dir/third_party/wpcap/include/* $include_dir
fi

[[ -d $tmp_dir ]] || mkdir -p $tmp_dir
cd $tmp_dir
eval "cmake .. -DCMAKE_BUILD_TYPE=$build_type $generate_options"
eval "cmake --build . --config $build_type $build_options"
cd -

echo "build completion."
