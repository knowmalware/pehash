
import pehash
import pefile

class TestTotalhash(object):

    def test_7zip(self):
        assert pehash.totalhash_hex('7z465.exe') == '4a78d5d83ea85c534be7bffc00e6637616e44bf9'

    def test_firefox(self):
        assert pehash.totalhash_hex('firefox-37-0-2.exe') == 'fa5d5ddc17249ff3b884934bf292994bac4923aa'

    def test_winrar(self):
        assert pehash.totalhash_hex('winrar-x64-521.exe') == None


class TestAnymaster(object):

    def test_7zip(self):
        assert pehash.anymaster_hex('7z465.exe') == '662e3a3c1e5430c51d25e7adfb18b22b3c4cd161'

    def test_firefox(self):
        assert pehash.anymaster_hex('firefox-37-0-2.exe') == '610aaf0f4989888192218bc2b947d1385923d28f'

    def test_winrar(self):
        assert pehash.anymaster_hex('winrar-x64-521.exe') == '026ce32731cb09062b8292d8a9e33d5e93276dec'


class TestAnymaster101(object):

    def test_7zip(self):
        assert pehash.anymaster_v1_0_1_hex('7z465.exe') == '085a8a3454183adadc20cbe2f034b98fa2a4d775'

    def test_firefox(self):
        assert pehash.anymaster_v1_0_1_hex('firefox-37-0-2.exe') == 'a1236c3db1602ee2cc6214a94856cbcee9989526'

    def test_winrar(self):
        assert pehash.anymaster_v1_0_1_hex('winrar-x64-521.exe') == '0c1375ff3aa7b960eb80b540472f71a05b58923c'


class TestEndgame(object):

    def test_7zip(self):
        assert pehash.endgame_hex('7z465.exe') == 'dd00a9c21914d71758a3e22dc3430631'

    def test_firefox(self):
        assert pehash.endgame_hex('firefox-37-0-2.exe') == '1aaf460d0e422091a9985bde222ec0ff'

    def test_winrar(self):
        assert pehash.endgame_hex('winrar-x64-521.exe') == 'adce64dd14c6ff1ddbcd155c56621e88'


class TestCrits(object):

    def test_7zip(self):
        assert pehash.crits_hex('7z465.exe') == '60046843c85b94f87bdc9be5f9ecae7983f83d43'

    def test_firefox(self):
        assert pehash.crits_hex('firefox-37-0-2.exe') == '1729dbba4aa062a7784ce6e057a27a2479d53df7'

    def test_winrar(self):
        assert pehash.crits_hex('winrar-x64-521.exe') == None

