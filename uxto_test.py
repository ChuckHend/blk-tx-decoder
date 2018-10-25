import unittest
import uxto

class TransactionTest(unittest.TestCase):
  """ The test for transation."""
  def setUp(self):
    self._uxto = uxto.Uxto(":memory:")

  def test_insert_and_clear(self):
    self._uxto.insert({"a": 1, "b": 1, 'c': 2})
    self._uxto.info()
    self._uxto.clear(set(['a', 'c']))
    self.assertEqual(self._uxto.info()[0], 1)

  def test_clear_ret(self):
    self._uxto.insert({"a": 1, "b": 1, 'c': 2})
    self._uxto.info()
    self.assertTrue('e' in self._uxto.clear(set(['a', 'c', 'e'])))

  def test_insert(self):
    self._uxto.insert({"a": 1, "b": 1, 'c': 2})
    self.assertTrue(self._uxto.info()[0], 3)
    self.assertTrue(self._uxto.info()[1], 4)


if __name__ == '__main__':
    unittest.main()