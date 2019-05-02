
import pehash
import pefile
import pytest
import json


with open("test_data.json", "r") as fh:
    test_data = json.load(fh)


class TestTotalhash(object):

    def test_totalhash(self):
        for d in test_data:
            assert pehash.totalhash_hex(d["filename"]) == d["pehash"]["totalhash"]


class TestAnymaster(object):

    def test_anymaster(self):
        for d in test_data:
            assert pehash.anymaster_hex(d["filename"]) == d["pehash"]["anymaster"]


class TestAnymaster101(object):

    def test_anymaster101(self):
        for d in test_data:
            assert pehash.anymaster_v1_0_1_hex(d["filename"]) == d["pehash"]["anymaster_v1_0_1"]


class TestEndgame(object):

    def test_endgame(self):
        for d in test_data:
            assert pehash.endgame_hex(d["filename"]) == d["pehash"]["endgame"]


class TestCrits(object):

    def test_crits(self):
        for d in test_data:
            assert pehash.crits_hex(d["filename"]) == d["pehash"]["crits"]


class TestPehashng(object):

    def test_pehashng(self):
        for d in test_data:
            assert pehash.pehashng_hex(d["filename"]) == d["pehash"]["pehashng"]


class TestExceptions(object):

    def test_totalhash(self):
        for d in test_data:
            if d["pehash"]["totalhash"] is None:
                with pytest.raises(ValueError):
                    pehash.totalhash_hex(d["filename"], raise_on_error=True)

