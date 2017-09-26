#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Known peHash implementations that differ in result.

Several tools currently use a TotalHash-compatible implementation, however
the malware analysis and research communities have not yet clearly chosen
a winner.  This modules provides a unified interface to all known peHash
implementations.

References specific to each implementation are in each function's docs.

For a discussion of known problems with the TotalHash-compatible
implementations, see https://gist.github.com/wxsBSD/07a5709fdcb59d346e9e

All functions in this module take the same arguments and return either
a hasher object, a string of the hexadecimal-encoded hash value, or
None on error.

Arguments:
    file\_path: the path to a PE file on disk.  Will be passed to
        pefile.PE(...)
    pe: an instantiated pefile.PE object.
    file\_data: a buffer containing the data for a PE file.  Will be
        passed to pefile.PE(...)
    hasher: an object that implements .update(data).  If given to the
        *_hex functions, must also implement .hexdigest().  The hash
        objects from the hashlib library support this API.
        Example:  hasher=hashlib.sha256()
    raise\_on\_error: if set to True, then will raise any exceptions.
        Otherwise, will return None on any exception.

Original paper:
    Wicherski, Georg. 2009. peHash: a novel approach to fast malware clustering.
    In Proceedings of the 2nd USENIX conference on Large-scale exploits and
    emergent threats: botnets, spyware, worms, and more (LEET'09). USENIX
    Association, Berkeley, CA, USA, 1-1.
    https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski.pdf
"""

from __future__ import division

import sys
import argparse
import bz2
import string
import hashlib
import pefile
import bitstring
import struct

def totalhash(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Given a PE file, calculate the pehash using the
    TotalHash / Viper implementation.

    For a description of the arguments, see the module documenation.

    If no hasher is given, uses hashlib.sha1()

    To obtain the hash, call hexdigest(), for example:
        myPE = pefile.PE('myfile.bin')
        sha1_obj = totalhash(pe=myPE)
        print sha1_obj.hexdigest()

    Reference:
      https://github.com/viper-framework/viper/blob/master/viper/modules/pehash/pehasher.py
    """
    # Based upon pehasher.py from viper source code, which is:
    #   Copyright (c) 2013, Claudio "nex" Guarnieri
    #   All rights reserved.
    #   See the file https://github.com/kevthehermit/viper/blob/b504647a618044d89f74c8334ed481cb7101359a/LICENSE
    #
    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        #image characteristics
        img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
        #pad to 16 bits
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:8] ^ img_chars[8:16]

        #start to build pehash
        pehash_bin = bitstring.BitArray(img_chars_xor)

        #subsystem - 
        sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
        #pad to 16 bits
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
        pehash_bin.append(sub_chars_xor)

        #Stack Commit Size
        stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        #now xor the bits
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
        #pad to 8 bits
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        #Heap Commit Size
        hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        #now xor the bits
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
        #pad to 8 bits
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        #Section chars
        for section in exe.sections:
            #virutal address
            sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            sect_va_bits = sect_va[8:32]
            pehash_bin.append(sect_va_bits)

            #rawsize
            sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:32]
            pehash_bin.append(sect_rs_bits)

            #section chars
            sect_chars =  bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
            pehash_bin.append(sect_chars_xor)

            #entropy calulation
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.write()[address+size:]
            if size == 0: 
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:8])
                continue
            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            #k = round(bz2_size / size, 5)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:8])

        if not hasher:
            hasher = hashlib.sha1()
        hasher.update(pehash_bin.tobytes())
        return hasher

    except Exception as e:
        if raise_on_error:
            raise
        else:
            return None


def anymaster(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Given a PE file, calculate the pehash using the
    AnyMaster implementation.

    For a description of the arguments, see the module documenation.

    If no hasher is given, uses hashlib.sha1()

    To obtain the hash, call hexdigest(), for example:
        myPE = pefile.PE('myfile.bin')
        sha1_obj = totalhash(pe=myPE)
        print sha1_obj.hexdigest()

    Reference:
      https://github.com/AnyMaster/pehash
    """
    # Based upon the AnyMaster v1.0.1 implementation of pehash
    # from https://github.com/AnyMaster/pehash
    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        # Image Characteristics
        img_chars = bitstring.pack('uint:16', exe.FILE_HEADER.Characteristics)
        pehash_bin = img_chars[0:8] ^ img_chars[8:16]

        # Subsystem
        subsystem = bitstring.pack('uint:16', exe.OPTIONAL_HEADER.Subsystem)
        pehash_bin.append(subsystem[0:8] ^ subsystem[8:16])

        # Stack Commit Size, rounded up to a value divisible by 4096,
        # Windows page boundary, 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        stack_commit = exe.OPTIONAL_HEADER.SizeOfStackCommit
        if stack_commit % 4096:
            stack_commit += 4096 - stack_commit % 4096
        stack_commit = bitstring.pack('uint:56', stack_commit >> 8)
        pehash_bin.append(
            stack_commit[:8] ^ stack_commit[8:16] ^
            stack_commit[16:24] ^ stack_commit[24:32] ^
            stack_commit[32:40] ^ stack_commit[40:48] ^ stack_commit[48:56])

        # Heap Commit Size, rounded up to page boundary size,
        # 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        heap_commit = exe.OPTIONAL_HEADER.SizeOfHeapCommit
        if heap_commit % 4096:
            heap_commit += 4096 - heap_commit % 4096
        heap_commit = bitstring.pack('uint:56', heap_commit >> 8)
        pehash_bin.append(
            heap_commit[:8] ^ heap_commit[8:16] ^
            heap_commit[16:24] ^ heap_commit[24:32] ^
            heap_commit[32:40] ^ heap_commit[40:48] ^ heap_commit[48:56])

        # Section structural information
        for section in exe.sections:
            # Virtual Address, 9 lower bits must be discarded
            pehash_bin.append(bitstring.pack('uint:24', section.VirtualAddress >> 9))

            # Size Of Raw Data, 8 lower bits must be discarded
            pehash_bin.append(bitstring.pack('uint:24', section.SizeOfRawData >> 8))

            # Section Characteristics, 16 lower bits must be discarded
            sect_chars = bitstring.pack('uint:16', section.Characteristics >> 16)
            pehash_bin.append(sect_chars[:8] ^ sect_chars[8:16])

            # Kolmogorov Complexity, len(Bzip2(data))/len(data)
            # (0..1} ∈ R   ->  [0..7] ⊂ N
            kolmogorov = 0
            if section.SizeOfRawData:
                kolmogorov = int(round(
                    len(bz2.compress(section.get_data()))
                    * 7.0 /
                    section.SizeOfRawData))
                if kolmogorov > 7:
                    kolmogorov = 7
            pehash_bin.append(bitstring.pack('uint:8', kolmogorov))

        assert 0 == pehash_bin.len % 8
        if not pe:
            exe.close()

        if not hasher:
            hasher = hashlib.sha1()
        hasher.update(pehash_bin.tobytes())
        return hasher
    except Exception as e:
        if raise_on_error:
            raise
        else:
            return None


def anymaster_v1_0_1(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Given a PE file, calculate the pehash using the
    AnyMaster implementation v1.0.1, which uses pe.FILE_HEADER.Machine
    in subsystem bitstring.

    For a description of the arguments, see the module documenation.

    If no hasher is given, uses hashlib.sha1()

    To obtain the hash, call hexdigest(), for example:
        myPE = pefile.PE('myfile.bin')
        sha1_obj = totalhash(pe=myPE)
        print sha1_obj.hexdigest()

    Reference:
      https://github.com/AnyMaster/pehash
    """
    # Based upon the AnyMaster v1.0.1 implementation of pehash
    # from https://github.com/AnyMaster/pehash
    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        # Image Characteristics
        img_chars = bitstring.pack('uint:16', exe.FILE_HEADER.Characteristics)
        pehash_bin = img_chars[0:8] ^ img_chars[8:16]

        # Subsystem
        subsystem = bitstring.pack('uint:16', exe.FILE_HEADER.Machine)
        pehash_bin.append(subsystem[0:8] ^ subsystem[8:16])

        # Stack Commit Size, rounded up to a value divisible by 4096,
        # Windows page boundary, 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        stack_commit = exe.OPTIONAL_HEADER.SizeOfStackCommit
        if stack_commit % 4096:
            stack_commit += 4096 - stack_commit % 4096
        stack_commit = bitstring.pack('uint:56', stack_commit >> 8)
        pehash_bin.append(
            stack_commit[:8] ^ stack_commit[8:16] ^
            stack_commit[16:24] ^ stack_commit[24:32] ^
            stack_commit[32:40] ^ stack_commit[40:48] ^ stack_commit[48:56])

        # Heap Commit Size, rounded up to page boundary size,
        # 8 lower bits must be discarded
        # in PE32+ is 8 bytes
        heap_commit = exe.OPTIONAL_HEADER.SizeOfHeapCommit
        if heap_commit % 4096:
            heap_commit += 4096 - heap_commit % 4096
        heap_commit = bitstring.pack('uint:56', heap_commit >> 8)
        pehash_bin.append(
            heap_commit[:8] ^ heap_commit[8:16] ^
            heap_commit[16:24] ^ heap_commit[24:32] ^
            heap_commit[32:40] ^ heap_commit[40:48] ^ heap_commit[48:56])

        # Section structural information
        for section in exe.sections:
            # Virtual Address, 9 lower bits must be discarded
            pehash_bin.append(bitstring.pack('uint:24', section.VirtualAddress >> 9))

            # Size Of Raw Data, 8 lower bits must be discarded
            pehash_bin.append(bitstring.pack('uint:24', section.SizeOfRawData >> 8))

            # Section Characteristics, 16 lower bits must be discarded
            sect_chars = bitstring.pack('uint:16', section.Characteristics >> 16)
            pehash_bin.append(sect_chars[:8] ^ sect_chars[8:16])

            # Kolmogorov Complexity, len(Bzip2(data))/len(data)
            # (0..1} ∈ R   ->  [0..7] ⊂ N
            kolmogorov = 0
            if section.SizeOfRawData:
                kolmogorov = int(round(
                    len(bz2.compress(section.get_data()))
                    * 7.0 /
                    section.SizeOfRawData))
                if kolmogorov > 7:
                    kolmogorov = 7
            pehash_bin.append(bitstring.pack('uint:8', kolmogorov))

        assert 0 == pehash_bin.len % 8
        if not pe:
            exe.close()

        if not hasher:
            hasher = hashlib.sha1()
        hasher.update(pehash_bin.tobytes())
        return hasher
    except Exception as e:
        if raise_on_error:
            raise
        else:
            return None


##################################################
import math
import copy

def _roundUp(num):
    winPageBoundary = 4096.
    return int(math.ceil(num/winPageBoundary) * winPageBoundary)


def endgame(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Given a PE file, calculate the pehash using the
    endgameinc implementation.

    For a description of the arguments, see the module documenation.

    If no hasher is given, uses hashlib.md5()

    To obtain the hash, call hexdigest(), for example:
        myPE = pefile.PE('myfile.bin')
        sha1_obj = totalhash(pe=myPE)
        print sha1_obj.hexdigest()

    This implementation appears to be an attempt to "fix" the totalhash
    implementation by using a more precise method of obtaining each
    section's data.

    Reference:
      https://github.com/endgameinc/pehashd/blob/master/pehashd.py
    """
    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        characteristics = bitstring.BitArray(uint=exe.FILE_HEADER.Characteristics, length=16)
        subsystem = bitstring.BitArray(uint=exe.OPTIONAL_HEADER.Subsystem, length=16)

        # Rounded up to page boundary size
        sizeOfStackCommit = bitstring.BitArray(uint=_roundUp(exe.OPTIONAL_HEADER.SizeOfStackCommit), length=32)
        sizeOfHeapCommit = bitstring.BitArray(uint=_roundUp(exe.OPTIONAL_HEADER.SizeOfHeapCommit), length=32)

        #sort these:
        sections = [];
        for section in exe.sections:
            #calculate kolmogrov:
            data = exe.get_memory_mapped_image()[section.VirtualAddress: section.VirtualAddress + section.SizeOfRawData]
            compressedLength = len(bz2.compress(data))

            kolmogrov = 0
            if (section.SizeOfRawData > 0):
                kolmogrov = int(math.ceil((compressedLength/section.SizeOfRawData) * 7.))

            sections.append((section.Name, bitstring.BitArray(uint=section.VirtualAddress, length=32),bitstring.BitArray(uint=section.SizeOfRawData, length=32),bitstring.BitArray(uint=section.Characteristics, length=32),bitstring.BitArray(uint=kolmogrov, length=16)))
        hash = characteristics[0:8] ^ characteristics[8:16]
        characteristics_hash = characteristics[0:8] ^ characteristics[8:16]
        hash.append(subsystem[0:8] ^ subsystem[8:16])
        subsystem_hash = subsystem[0:8] ^ subsystem[8:16]
        hash.append(sizeOfStackCommit[8:16] ^ sizeOfStackCommit[16:24] ^ sizeOfStackCommit[24:32])
        stackcommit_hash = sizeOfStackCommit[8:16] ^ sizeOfStackCommit[16:24] ^ sizeOfStackCommit[24:32]
        hash.append(sizeOfHeapCommit[8:16] ^ sizeOfHeapCommit[16:24] ^ sizeOfHeapCommit[24:32])
        heapcommit_hash = sizeOfHeapCommit[8:16] ^ sizeOfHeapCommit[16:24] ^ sizeOfHeapCommit[24:32]

        sections_holder = []
        for section in sections:
            section_copy = copy.deepcopy(section)
            section_hash = section_copy[1]
            section_hash.append(section_copy[2])
            section_hash.append(section_copy[3][16:24] ^ section_copy[3][24:32])
            section_hash.append(section_copy[4])
            hash.append(section[1])
            hash.append(section[2])
            hash.append(section[3][16:24] ^ section[3][24:32])
            hash.append(section[4])

            sections_holder.append(str(section_hash))

        if not hasher:
            hasher = hashlib.md5()
        hasher.update(str(hash))
        return hasher

    except Exception as e:
        if raise_on_error:
            raise
        else:
            return None


def crits(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Given a PE file, calculate the pehash using the
    crits implementation.

    For a description of the arguments, see the module documenation.

    If no hasher is given, uses hashlib.sha1()

    To obtain the hash, call hexdigest(), for example:
        myPE = pefile.PE('myfile.bin')
        sha1_obj = totalhash(pe=myPE)
        print sha1_obj.hexdigest()

    Almost exactly the same as the totalhash-compatibale implementation,
    except misses several bits due to off-by-one errors with list slice
    indices.

    Reference:
      https://github.com/crits/crits_services/blob/master/peinfo_service/__init__.py
    """
    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        #image characteristics
        img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
        #pad to 16 bits
        if len(img_chars) == 8:
            img_chars = bitstring.BitArray('0b00000000') + img_chars
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

        #start to build pehash
        pehash_bin = bitstring.BitArray(img_chars_xor)

        #subsystem -
        sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
        #pad to 16 bits
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
        pehash_bin.append(sub_chars_xor)

        #Stack Commit Size
        stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        #now xor the bits
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
        #pad to 8 bits
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        #Heap Commit Size
        hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        #now xor the bits
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
        #pad to 8 bits
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        #Section chars
        for section in exe.sections:
            #virutal address
            sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            pehash_bin.append(sect_va)

            #rawsize
            sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:31]
            pehash_bin.append(sect_rs_bits)

            #section chars
            sect_chars =  bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
            pehash_bin.append(sect_chars_xor)

            #entropy calulation
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.write()[address+size:]
            if size == 0:
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:7])
                continue
            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            #k = round(bz2_size / size, 5)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:7])

        if not hasher:
            hasher = hashlib.sha1()
        hasher.update(pehash_bin.tobytes())
        return hasher

    except Exception as why:
        if raise_on_error:
            raise
        else:
            return None

def pehashng(file_path, pe, file_data, hasher, raise_on_error):
    """ Return pehashng for PE file, sha256 of PE structural properties.
    :param pe_file: file name or instance of pefile.PE() class
    :return: SHA256 in hexdigest format, None in case of pefile.PE() error
    :rtype: str
    """

    def align_down_p2(number):
        return 1 << (number.bit_length() - 1) if number else 0

    def align_up(number, boundary_p2):
        assert not boundary_p2 & (boundary_p2 - 1), \
            "Boundary '%d' is not a power of 2" % boundary_p2
        boundary_p2 -= 1
        return (number + boundary_p2) & ~ boundary_p2

    def get_dirs_status():
        dirs_status = 0
        for idx in range(min(exe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):
            if exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress:
                dirs_status |= (1 << idx)
        return dirs_status

    def get_complexity():
        complexity = 0
        if section.SizeOfRawData:
            complexity = (len(bz2.compress(section.get_data())) *
                          7.0 /
                          section.SizeOfRawData)
            complexity = 8 if complexity > 7 else int(round(complexity))
        return complexity


    if not pe:
        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception('No valid arguments provided')
                return None
        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe



    try:

        characteristics_mask = 0b0111111100100011
        data_directory_mask = 0b0111111001111111

        data = [
            struct.pack('> H', exe.FILE_HEADER.Characteristics & characteristics_mask),
            struct.pack('> H', exe.OPTIONAL_HEADER.Subsystem),
            struct.pack("> I", align_down_p2(exe.OPTIONAL_HEADER.SectionAlignment)),
            struct.pack("> I", align_down_p2(exe.OPTIONAL_HEADER.FileAlignment)),
            struct.pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfStackCommit, 4096)),
            struct.pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfHeapCommit, 4096)),
            struct.pack('> H', get_dirs_status() & data_directory_mask)]

        for section in exe.sections:
            data += [
                struct.pack('> I', align_up(section.VirtualAddress, 512)),
                struct.pack('> I', align_up(section.SizeOfRawData, 512)),
                struct.pack('> B', section.Characteristics >> 24),
                struct.pack("> B", get_complexity())]

        hasher = hashlib.sha256(b"".join(data))
        return hasher
    except Exception as why:
        if raise_on_error:
            raise
        else:
            return None


def totalhash_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as totalhash(...) but returns either str hex digest or None."""
    hd = totalhash(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()


def anymaster_v1_0_1_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as anymaster_v1_0_1(...) but returns either str hex digest or None."""
    hd = anymaster_v1_0_1(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()


def anymaster_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as anymaster(...) but returns either str hex digest or None."""
    hd = anymaster(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()


def endgame_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as endgame(...) but returns either str hex digest or None."""
    hd = endgame(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()


def crits_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as crits(...) but returns either str hex digest or None."""
    hd = crits(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()

def pehashng_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    """Same as pehashng(...) but returns either str hex digest or None."""
    hd = pehashng(file_path, pe, file_data, hasher, raise_on_error)
    if hd:
        return hd.hexdigest()


##################################################
def main():

    parser = argparse.ArgumentParser(description='Process pehash in different ways')
    parser.add_argument('--totalhash', dest='totalhash', action='store_true',
                        default=False, help="Generate totalhash pehash")
    parser.add_argument('--anymaster', dest='anymaster', action='store_true',
                        default=False, help="Generate anymaster pehash")
    parser.add_argument('--anymaster_v1', dest='anymaster_v1', action='store_true',
                        default=False, help="Generate anymaster v1.0.1 pehash")
    parser.add_argument('--endgame', dest='endgame', action='store_true',
                        default=False, help="Generate endgame pehash")
    parser.add_argument('--crits', dest='crits', action='store_true',
                        default=False, help="Generate crits pehash")
    parser.add_argument('--pehashng', dest='pehashng', action='store_true',
                        default=False, help="Generate pehashng (https://github.com/AnyMaster/pehashng)")
    parser.add_argument('-v', dest='verbose', action='count',
                        help="Raise pehash exceptions instead of ignoring.")

    parser.add_argument('binaries', metavar='binaries', type=str, nargs='+',
                        help='list of pe files to process')

    args = parser.parse_args()

    for binary in args.binaries:
        try:
            pe = pefile.PE(binary)
            do_all = not (args.totalhash or args.anymaster or args.anymaster_v1 or
                    args.endgame or args.crits or args.pehashng)
            raise_on_error = True if args.verbose > 0 else False
            if args.totalhash or do_all:
                print("{}\tTotalhash\t{}".format(binary, totalhash_hex(pe=pe, raise_on_error=raise_on_error)))
            if args.anymaster or do_all:
                print("{}\tAnyMaster\t{}".format(binary, anymaster_hex(pe=pe, raise_on_error=raise_on_error)))
            if args.anymaster_v1 or do_all:
                print("{}\tAnyMaster_v1.0.1\t{}".format(binary, anymaster_v1_0_1_hex(pe=pe, raise_on_error=raise_on_error)))
            if args.endgame or do_all:
                print("{}\tEndGame\t{}".format(binary, endgame_hex(pe=pe, raise_on_error=raise_on_error)))
            if args.crits or do_all:
                print("{}\tCrits\t{}".format(binary, crits_hex(pe=pe, raise_on_error=raise_on_error)))
            if args.pehashng or do_all:
                print("{}\tpeHashNG\t{}".format(binary, pehashng_hex(pe=pe, raise_on_error=raise_on_error)))
        except pefile.PEFormatError:
            print("ERROR: {} is not a PE file".format(binary))

if __name__ == '__main__':
    main()
