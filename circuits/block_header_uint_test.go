package circuits

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
	"github.com/lightec-xyz/common/operations"
	"github.com/readygo67/BlockHeaderProver/utils"
	"testing"
)

/*
b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e27362400000000
"01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed",
"010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b",
"010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4",
*/
var (
	headers = []string{
		"01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed",
		"010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b",
		"010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4",
	}

	unitCcsFile      = "../testdata/block_header_unit.ccs"
	unitPkFile       = "../testdata/block_header_unit.pk"
	unitVkFile       = "../testdata/block_header_unit.vk"
	recursiveCcsFile = "../testdata/block_header_recursive.ccs"
	recursivePkFile  = "../testdata/block_header_recursive.pk"
	recursiveVkFile  = "../testdata/block_header_recursive.vk"
)

func TestBlockHeaderUnitCircuit_Simulation(t *testing.T) {
	assert := test.NewAssert(t)

	//header, err := hex.DecodeString("0080a92aebe493bf5f6af819788216e5cf6abc751fb39b926f57d2f594903700000000000a29327c7997d5f8abf5b7869e90fad470b9cb5051e02319975201b90356ba28636e1a6650e2261973343a08")
	header, err := hex.DecodeString("01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed")
	assert.NoError(err)
	hash := chainhash.DoubleHashH(header)
	vk, err := operations.ReadVk(unitVkFile)
	vkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)

	circuit := NewBlockHeaderUnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]()
	assignment := NewBlockHeaderUnitAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hash, [80]byte(header), vkFpBytes)

	ccs, err := operations.NewConstraintSystem(circuit)
	assert.NoError(err)
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBlockHeaderUnitCircuit_Plonk254(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := NewBlockHeaderUnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]()

	ccs, err := operations.NewConstraintSystem(circuit)
	assert.NoError(err)
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())
	srs, lsrs, err := operations.ReadSrs(ccs.GetNbConstraints()+ccs.GetNbPublicVariables(), "../srs")
	assert.NoError(err)

	pk, vk, err := operations.PlonkSetup(ccs, srs, lsrs)
	assert.NoError(err)

	err = operations.WriteCcs(ccs, unitCcsFile)
	assert.NoError(err)
	err = operations.WritePk(pk, unitPkFile)
	assert.NoError(err)
	err = operations.WriteVk(vk, unitVkFile)
	assert.NoError(err)

	vkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)
	fmt.Printf("vkFpBytes:%v\n", hex.EncodeToString(vkFpBytes))

	for i := 0; i < 3; i++ {
		header, err := hex.DecodeString(headers[i])
		assert.NoError(err)
		hash := chainhash.DoubleHashH(header)
		assignment := NewBlockHeaderUnitAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hash, [80]byte(header), vkFpBytes)

		proof, wit, err := operations.PlonkProve(ccs, pk, assignment, false)
		assert.NoError(err)

		err = operations.PlonkVerify(vk, proof, wit, false)
		assert.NoError(err)

		proofFile := fmt.Sprintf("../testdata/block_header_unit_%v.proof", i)
		witnessFile := fmt.Sprintf("../testdata/block_header_unit_%v.wtns", i)

		err = operations.WriteProof(proof, proofFile)
		assert.NoError(err)
		err = operations.WriteWitness(wit, witnessFile)
		assert.NoError(err)

	}

}
