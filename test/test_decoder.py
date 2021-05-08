from decoder.utils import (
    BlockFile
)


def test_file():
    b = BlockFile("./test/blk00TEST00.dat")
    b.get_all_blocks()

    assert len(b.transactions) == 4583

    assert b.block_file_identifier == "00TEST00"

