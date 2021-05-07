# This file is part of Elsim
#
# Copyright (C) 2019, Sebastian Bachmann <hello at reox.at>
# All rights reserved.
#
# Elsim is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Elsim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Elsim.  If not, see <http://www.gnu.org/licenses/>.
from setuptools import setup, find_packages, Extension


setup(
    name='elsim',
    version='0.2.0',
    description='Elsim is a library designed to detect similar content in files, especially in the context of Android',
    packages=find_packages(),
    install_requires=[
        "androguard @ https://github.com/themoep/androguard/tarball/master",  # require version 3.4.0 or latest master
        "python-hashes @ https://github.com/sean-public/python-hashes/tarball/master",  # require version >0.2, which is not yet on pypi
        "click",
        "murmurhash3",
        "tqdm",
        "sphinx>=2.2.0",  # for docs only
        "numpy",  # only used once, not sure if actual dependency or just some optional stuff
        "sklearn",  # only used once, not sure if actual dependency or just some optional stuff
    ],
    entry_points={
        "console_scripts": [
            "dalviksim = elsim.cli.dalviksim:cli",
            "textsim = elsim.cli.textsim:cli",
            "elsimbenchmark = elsim.cli.benchmark:cli",
            "androdb = elsim.cli.androdb:cli",
            "androsign = elsim.cli.androsign:cli",
            ],
        },
    ext_modules=[
        Extension(
            'elsim.similarity.libsimilarity',
            sources=['elsim/similarity/similarity.c',
                     'elsim/similarity/bz2/bz2.c',
                     'elsim/similarity/lzma/Alloc.c',
                     'elsim/similarity/lzma/LzFind.c',
                     'elsim/similarity/lzma/LzmaDec.c',
                     'elsim/similarity/lzma/LzmaEnc.c',
                     'elsim/similarity/lzma/LzmaLib.c',
                     'elsim/similarity/lzma/lzma.c',
                     'elsim/similarity/smaz/smaz.c',
                     'elsim/similarity/snappy/snappy.cc',
                     'elsim/similarity/vcblocksort/vcblocksort.c',
                     'elsim/similarity/xz/xz.c',
                     'elsim/similarity/z/z.c',
                     ],
            libraries=['lzma', 'snappy', 'bz2', 'z'],
            extra_compile_args=[
                '-D_7ZIP_ST',  # required for LZMA
            ],
        ),
        Extension(
            'elsim.elsign.libelsign',
            sources=['elsim/elsign/elsign.cc',
                     'elsim/elsign/ac_heap.c',
                     'elsim/elsign/ac_list.c',
                     'elsim/elsign/aho_corasick.c',
                     'elsim/elsign/cluster.c',
                     'elsim/elsign/formula.cc',

                     # FIXME: this is a crude hack to get it to work!!!
                     # idealy, one would link against the other library, but this seems to be very hard to do...
                     'elsim/similarity/similarity.c',
                     'elsim/similarity/bz2/bz2.c',
                     'elsim/similarity/lzma/Alloc.c',
                     'elsim/similarity/lzma/LzFind.c',
                     'elsim/similarity/lzma/LzmaDec.c',
                     'elsim/similarity/lzma/LzmaEnc.c',
                     'elsim/similarity/lzma/LzmaLib.c',
                     'elsim/similarity/lzma/lzma.c',
                     'elsim/similarity/smaz/smaz.c',
                     'elsim/similarity/snappy/snappy.cc',
                     'elsim/similarity/vcblocksort/vcblocksort.c',
                     'elsim/similarity/xz/xz.c',
                     'elsim/similarity/z/z.c',
                    ],
            libraries=['muparser', 'lzma', 'snappy', 'bz2', 'z'],
            include_dirs=['elsim/similarity'],
            extra_compile_args=[
                '-D_GLIBCXX_PERMIT_BACKWARD_HASH',  # required for sparsehash
                '-D_7ZIP_ST',  # required for LZMA
                ],
        )
    ],

)
