This is a simple bitcoin block parser tools. which is a fork of block chain tools.

- Support Segwit block.
- Address has been encoded by Base58.
- Support basic payment methods.   

## Bitcoin block parser

Bitcoin block parser implementation written in python3.

- blocktools.py - tools for reading binary data from block files
- block.py - classes for Blocks, Transactions
- check.py - Iterate the block
- sight.py - Another example to iterate the block.
- 5megs.dat - first 5 megs from blk00000.dat
- 1M.dat - first 1M from blk00000.dat
- blk01234.001 - first 1.4M from blk01234.dat, segwit enabled.

## Usage

```
python3 sight.py blk01234.001
```

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## License

BSD 3
