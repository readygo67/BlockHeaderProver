## How to handle Error downloading object: srs/bn254_pow_19.lsrs
```sh
GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/readygo67/BlockHeaderProver-Gnark.git
cd BlockHeaderProver-Gnark
git lfs install --skip-smudge  # disable automatic download LFS files
```


## BlockHeaderProver

```sh
cd cmd
go build
./cmd 
```

## Implementation on SP1
https://github.com/readygo67/BlockHeaderProver-SP1
