import unittest
import uxto_memory

class TransactionTest(unittest.TestCase):
  """ The test for transaction."""
  def setUp(self):
    self._uxto = uxto_memory.Uxto("test")

  def test_insert_and_clear(self):
    self._uxto.insert({('a', 1): 1, ('b', 1): 1,  ('c', 9): 2})
    self._uxto.info()
    self._uxto.clear(set([('a', 1), ('c', 9)]))
    self.assertEqual(self._uxto.info()[0], 1)

  def test_clear_ret(self):
    self._uxto.insert({('a', 1): 1,('b', 1): 1, ('c', 9): 2})
    self._uxto.info()
    self.assertTrue(('e', 9) in self._uxto.clear(set([('a', 1),  ('c', 9),  ('e', 9)])))

  def test_insert_tx(self):
    self._uxto.insert({('a', 1): 1, ('b', 1): 1, ('c', 9): 2})
    self.assertTrue(self._uxto.info()[0], 3)
    self.assertTrue(self._uxto.info()[1], 4)

  def test_uxto_key(self):
    raw_hash = "abcd" * 16
    byte_key = uxto_memory.Uxto.uxto_key(raw_hash, 20)
    self.assertEqual(byte_key, b'\xab\xcd' * 16 + b'\x24')

    # odd idx
    byte_key = uxto_memory.Uxto.uxto_key(raw_hash, 64)
    self.assertEqual(byte_key, b'\xab\xcd' * 16 + b'\x01\x00')

  def test_key_uxto(self):
    raw_hash = "abcd" * 16
    self.assertEqual(uxto_memory.Uxto.key_uxto(b'\xab\xcd' * 16 + b'\x24'), (raw_hash, 20))
    self.assertEqual(uxto_memory.Uxto.key_uxto(b'\xab\xcd' * 16 + b'\x01\x00'), (raw_hash, 64))


if __name__ == '__main__':
    unittest.main()