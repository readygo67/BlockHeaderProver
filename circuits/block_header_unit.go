package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/readygo67/BlockHeaderProver/utils"
)

const BeginHashOffset = 4
const HashLen = 32
const BlockHeaderLen = 80

type Hash [HashLen]uints.U8

func (h Hash) AssertIsEqual(api frontend.API, other Hash) {
	for i := 0; i < HashLen; i++ {
		api.AssertIsEqual(h[i].Val, other[i].Val)
	}
}

type BlockHeaderUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginHash                 Hash                  `gnark:",public"`
	EndHash                   Hash                  `gnark:",public"`
	PlaceHolderForRecursiveFp utils.FingerPrint[FR] `gnark:",public"`
	BlockHeader               [BlockHeaderLen]uints.U8
}

func (c *BlockHeaderUnitCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	parentHash := Hash(c.BlockHeader[BeginHashOffset : BeginHashOffset+HashLen])
	parentHash.AssertIsEqual(api, c.BeginHash)

	hash, err := DoubleSha256(api, c.BlockHeader[:])
	if err != nil {
		return err
	}
	hash.AssertIsEqual(api, c.EndHash)
	return nil
}

func NewBlockHeaderUnitCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT]() frontend.Circuit {
	return &BlockHeaderUnitCircuit[FR, G1El, G2El, GtEl]{}
}

func NewBlockHeaderUnitAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	blockHash [HashLen]byte,
	blockHeader [BlockHeaderLen]byte,
	unitVkFpBytes utils.FingerPrintBytes,
) frontend.Circuit {

	_parentHash := Hash{}
	for i := 0; i < HashLen; i++ {
		_parentHash[i] = uints.NewU8(blockHeader[i+BeginHashOffset])
	}

	_blockHash := Hash{}
	for i := 0; i < HashLen; i++ {
		_blockHash[i] = uints.NewU8(blockHash[i])
	}

	_blockHeader := [BlockHeaderLen]uints.U8{}
	for i := 0; i < BlockHeaderLen; i++ {
		_blockHeader[i] = uints.NewU8(blockHeader[i])
	}

	unitVkFp := utils.FingerPrintFromBytes[FR](unitVkFpBytes)

	return &BlockHeaderUnitCircuit[FR, G1El, G2El, GtEl]{
		BeginHash:                 _parentHash,
		EndHash:                   _blockHash,
		PlaceHolderForRecursiveFp: unitVkFp,
		BlockHeader:               _blockHeader,
	}
}

func DoubleSha256(api frontend.API, data []uints.U8) (*Hash, error) {
	var sum []uints.U8
	{
		sha256, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		sha256.Write(data)
		sum = sha256.Sum()
	}

	{
		sha256, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		sha256.Write(sum)
		sum = sha256.Sum()

	}
	ret := Hash(sum)
	return &ret, nil
}
