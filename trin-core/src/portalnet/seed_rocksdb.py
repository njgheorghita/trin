import rocksdb
from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import to_hex, to_bytes
from pathlib import Path
import secrets
import rlp

db = rocksdb.DB("seed_test_x.db", rocksdb.Options(create_if_missing=True, num_levels=1))

#
# to make this work, you have to overwrite AtomicDB in py-evm to allow iteration
# eth/db/atomic.py
# class AtomicDB(BaseAtomicDB):
    # def __iter__(self):
        # return iter(self.wrapped_db)

    # def __len__(self):
        # return len(self.wrapped_db)

eth_tester = EthereumTester(PyEVMBackend())
chain = eth_tester.backend.chain

# add nodes to rocksdb
batch = rocksdb.WriteBatch()
for key, value in chain.chaindb.db.items():
    batch.put(key, value)
db.write(batch)

state_root = chain.get_block().header.state_root
print('state root: ', to_hex(state_root))

for acc in sorted(eth_tester.get_accounts()):
    print("account: ", acc)
