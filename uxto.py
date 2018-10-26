import sqlite3

class Uxto:
  """
  The Uxto on top of sqlite.
  :param sqlite_db_path: is the sqlite db, could use ":memory:" for test.
  """
  def __init__(self, sqlite_db_path):
    self._conn = sqlite3.connect(sqlite_db_path)
    cursor = self._conn.cursor()
    # cursor.execute("drop table uxto;")
    cursor.execute("CREATE TABLE uxto (tx_hash text, value int64);")
    # can not use unique index.
    # https://www.blockchain.com/btc/tx/d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
    cursor.execute("CREATE INDEX index_tx_hash ON uxto(tx_hash);")
    self._conn.commit()

  def info(self):
    """ return tuple of tx count and sume of value. """
    cursor = self._conn.cursor()
    cursor.execute("select count(1) cnt, sum(value) as value from uxto;")
    return cursor.fetchone()

  def insert(self, tx_dict):
    """
    Inserts all the transaction and corresponding value into uxto table.
    :param txs: the dict of {uxto(tx_hash+idx):value}
    """
    if len(tx_dict) > 0:
      cursor = self._conn.cursor()
      sql = "INSERT INTO uxto (tx_hash, value) VALUES " + ",".join(list(map(lambda t: "('%s', %d)" % (t[0], t[1]), tx_dict.items())))
      cursor.execute(sql)

  def clear(self, tx_set):
    """
    :param tx_set: key is uxto(tx_hash+idx) value is value.
    :return:
    """
    cursor = self._conn.cursor()
    if len(tx_set) == 0:
      return tx_set
    sql = "SELECT * from uxto INDEXED BY index_tx_hash where tx_hash in ('" + "','".join(tx_set) + "');"
    cursor.execute(sql)
    delete_tx_hash_set = set()
    for row_info in cursor.fetchall():
      uxto = row_info[0]
      if uxto in tx_set:
        tx_set.remove(uxto)
        delete_tx_hash_set.add(uxto)
    if len(delete_tx_hash_set) > 0:
      sql = "DELETE FROM uxto INDEXED BY index_tx_hash where tx_hash in ('" + "','".join(delete_tx_hash_set) + "');"
      cursor.execute(sql)
    return tx_set

  def commit(self):
    self._conn.commit()

  def vacuum(self):
    self._conn.execute("vacuum")


if __name__ == "__main__":
  uxto = Uxto("test");
  uxto.insert({"a": 1, "b": 1, 'c': 2})
  print(uxto.info())
  print(uxto.clear(set(['a', 'c'])))
  print(uxto.info())

