class Uxto:
    """
    The Uxto on top of a dict of key:(tx_hash, idx) value:value.
    :param name: only an identifier.
    """

    def __init__(self, name):
        self._name = name
        self._memory = {}
        self._value = 0
        self._uncommit_tx_counter = 0

    def info(self):
        """
        :return: tuple of (tx count, sum of value).
        """
        return len(self._memory), self._value

    def insert(self, tx_dict):
        """
        Inserts all the transaction and corresponding value into uxto table.
        :param tx_dict: the dict of {uxto(tx_hash, idx):value}
        """
        if len(tx_dict) > 0:
            for (tx_hash, idx), v in tx_dict.items():
                self._memory[self.uxto_key(tx_hash, idx)] = v
                self._value = self._value + v
            self._uncommit_tx_counter = self._uncommit_tx_counter + len(tx_dict)

    def clear(self, tx_set):
        """
        :param tx_set: key is uxto(tx_hash, idx).
        :return: the (tx_hash, idx) set that do not exist in uxto pool.
        """
        uk_tx_hash_idx_set = set()
        if len(tx_set) == 0:
            return uk_tx_hash_idx_set

        for raw_hash, idx in tx_set:
            hex_key = self.uxto_key(raw_hash, idx)
            if hex_key in self._memory:
                self._value = self._value - self._memory[hex_key]
                del self._memory[hex_key]
                self._uncommit_tx_counter = self._uncommit_tx_counter + 1
            else:
                uk_tx_hash_idx_set.add((raw_hash, idx))
            self._uncommit_tx_counter = self._uncommit_tx_counter + len(uk_tx_hash_idx_set)
        return uk_tx_hash_idx_set

    def commit(self):
        """
        :return: the number of tx_hash change, include adding tx_hash and removing tx_hash.
        """
        ret = self._uncommit_tx_counter
        self._uncommit_tx_counter = 0
        return ret

    @staticmethod
    def uxto_key(tx_hash, idx):
        """ Convert to hex of tx_hash and idx. """
        ret = "%s%o" % (tx_hash, idx)
        if len(ret) % 2 == 0:
            return bytes.fromhex(ret)
        else:
            return bytes.fromhex("%s0%o" % (tx_hash, idx))

    @staticmethod
    def key_uxto(bytes_key):
        hash_idx = bytes_key.hex()
        return hash_idx[:64], int(hash_idx[64:], 8)


if __name__ == "__main__":
    uxto = Uxto("test");
    uxto.insert({('a', 1): 1, ('b', 1): 1, ('c', 9): 2})
    print(uxto.info())
    print(uxto.clear(set([('a', 1), ('c', 9)])))
    print(uxto.info())
