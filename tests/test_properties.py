"""Generated inputs exercise codec and cross-file layout invariants."""
import tempfile
import unittest
from pathlib import Path

from hypothesis import given, settings, strategies as st

from app import bencode
from app.storage import Storage
from app.torrent import Torrent
from tools.swarm import metainfo

values = st.recursive(st.one_of(st.binary(max_size=100), st.integers(-10**12, 10**12)),
                      lambda children: st.one_of(st.lists(children, max_size=5),
                                                 st.dictionaries(st.text(alphabet='abc', min_size=1, max_size=5),
                                                                 children, max_size=5)), max_leaves=30)


class PropertyTests(unittest.TestCase):
    @given(values)
    @settings(max_examples=100, deadline=None)
    def test_canonical_roundtrip(self, value):
        self.assertEqual(bencode.decode(bencode.encode(value)), value)

    @given(st.binary(min_size=1, max_size=1000), st.integers(0, 1000))
    @settings(max_examples=30, deadline=None)
    def test_logical_layout_crosses_arbitrary_file_boundary(self, data, split):
        split %= len(data) + 1
        files = [(('a',), split), (('empty',), 0), (('nested', 'b'), len(data) - split)]
        torrent = Torrent.from_bytes(metainfo(data, piece_length=31, files=files))
        with tempfile.TemporaryDirectory() as directory, Storage(torrent, str(Path(directory) / 'out')) as store:
            for index in range(torrent.num_pieces):
                store.commit(index, data[index * 31:(index + 1) * 31])
            self.assertEqual(store.read(0, len(data)), data)
            store.publish()
            root = Path(directory) / 'out'
            self.assertEqual((root / 'a').read_bytes() + (root / 'nested' / 'b').read_bytes(), data)

