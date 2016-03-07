# pehash
Compilation of peHash implementations.

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

* file\_path: the path to a PE file on disk.  Will be passed to
  pefile.PE(...)
* pe: an instantiated pefile.PE object.
* file\_data: a buffer containing the data for a PE file.  Will be
  passed to pefile.PE(...)
* hasher: an object that implements .update(data).  If given to the
        *_hex functions, must also implement .hexdigest().  The hash
        objects from the hashlib library support this API.
        Example:  hasher=hashlib.sha256()
* raise\_on\_error: if set to True, then will raise any exceptions.
  Otherwise, will return None on any exception.

## Original paper:
    Wicherski, Georg. 2009. peHash: a novel approach to fast malware clustering.
    In Proceedings of the 2nd USENIX conference on Large-scale exploits and
    emergent threats: botnets, spyware, worms, and more (LEET'09). USENIX
    Association, Berkeley, CA, USA, 1-1.
    https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski.pdf
