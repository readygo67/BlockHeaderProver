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

func TestBlockHeaderRecursiveCircuit_Recursive_Setup(t *testing.T) {
	assert := test.NewAssert(t)

	unitCcs, err := operations.ReadCcs(unitCcsFile)
	assert.NoError(err)

	unitVk, err := operations.ReadVk(unitVkFile)
	assert.NoError(err)

	unitVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](unitVk)
	assert.NoError(err)

	circuit := NewBlockHeaderRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitCcs,
		unitVkFpBytes,
	)

	ccs, err := operations.NewConstraintSystem(circuit)
	assert.NoError(err)

	assert.NoError(err)
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())
	srs, lsrs, err := operations.ReadSrs(ccs.GetNbConstraints()+ccs.GetNbPublicVariables(), "../srs")
	assert.NoError(err)

	pk, vk, err := operations.PlonkSetup(ccs, srs, lsrs)
	assert.NoError(err)

	err = operations.WriteCcs(ccs, recursiveCcsFile)
	assert.NoError(err)
	err = operations.WritePk(pk, recursivePkFile)
	assert.NoError(err)
	err = operations.WriteVk(vk, recursiveVkFile)
	assert.NoError(err)
}

func TestBlockHeaderRecursiveCircuit_Recursive_0_2_Simulation(t *testing.T) {
	assert := test.NewAssert(t)

	firstProofFile := "../testdata/block_header_unit_0_1.proof"
	firstWitnessFile := "../testdata/block_header_unit_0_1.wtns"
	secondProofFile := "../testdata/block_header_unit_1_2.proof"
	secondWitnessFile := "../testdata/block_header_unit_1_2.wtns"

	_headers := make([][]byte, len(headers))
	hashes := make([][32]byte, len(headers))

	for i, h := range headers {
		_headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(_headers[i])
	}
	beignHash := [32]byte(_headers[0][4:36])

	unitCcs, err := operations.ReadCcs(unitCcsFile)
	assert.NoError(err)

	unitVk, err := operations.ReadVk(unitVkFile)
	assert.NoError(err)

	unitVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](unitVk)
	assert.NoError(err)

	circuit := NewBlockHeaderRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitCcs,
		unitVkFpBytes,
	)

	firstProof, err := operations.ReadProof(firstProofFile)
	assert.NoError(err)

	secondProof, err := operations.ReadProof(secondProofFile)
	assert.NoError(err)

	firstWitness, err := operations.ReadWitness(firstWitnessFile)
	assert.NoError(err)

	secondWitness, err := operations.ReadWitness(secondWitnessFile)
	assert.NoError(err)

	recursiveVk, err := operations.ReadVk(recursiveVkFile)
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	assignment, err := NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		beignHash,
		hashes[0],
		hashes[1],
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBlockHeaderRecursiveCircuit_Recursive_0_2_Plonk(t *testing.T) {
	assert := test.NewAssert(t)

	firstProofFile := "../testdata/block_header_unit_0_1.proof"
	firstWitnessFile := "../testdata/block_header_unit_0_1.wtns"
	secondProofFile := "../testdata/block_header_unit_1_2.proof"
	secondWitnessFile := "../testdata/block_header_unit_1_2.wtns"

	_headers := make([][]byte, len(headers))
	hashes := make([][32]byte, len(headers))

	for i, h := range headers {
		_headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(_headers[i])
	}
	beignHash := [32]byte(_headers[0][4:36])

	unitVk, err := operations.ReadVk(unitVkFile)
	assert.NoError(err)

	firstProof, err := operations.ReadProof(firstProofFile)
	assert.NoError(err)

	secondProof, err := operations.ReadProof(secondProofFile)
	assert.NoError(err)

	firstWitness, err := operations.ReadWitness(firstWitnessFile)
	assert.NoError(err)

	secondWitness, err := operations.ReadWitness(secondWitnessFile)
	assert.NoError(err)

	recursiveVk, err := operations.ReadVk(recursiveVkFile)
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	assignment, err := NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		beignHash,
		hashes[0],
		hashes[1],
	)

	recursiveCcs, err := operations.ReadCcs(recursiveCcsFile)
	assert.NoError(err)

	recursivePk, err := operations.ReadPk(recursivePkFile)
	assert.NoError(err)

	proof, witness, err := operations.PlonkProve(recursiveCcs, recursivePk, assignment, false)
	assert.NoError(err)

	err = operations.PlonkVerify(recursiveVk, proof, witness, false)
	assert.NoError(err)

	proofFile := "../testdata/block_header_recursive_0_2.proof"
	witnessFile := "../testdata/block_header_recursive_0_2.wtns"

	err = operations.WriteProof(proof, proofFile)
	assert.NoError(err)

	err = operations.WriteWitness(witness, witnessFile)
	assert.NoError(err)

}

func TestBlockHeaderRecursiveCircuit_Recursive_0_3_Simulation(t *testing.T) {
	assert := test.NewAssert(t)

	firstProofFile := "../testdata/block_header_recursive_0_2.proof"
	firstWitnessFile := "../testdata/block_header_recursive_0_2.wtns"
	secondProofFile := "../testdata/block_header_unit_2_3.proof"
	secondWitnessFile := "../testdata/block_header_unit_2_3.wtns"

	_headers := make([][]byte, len(headers))
	hashes := make([][32]byte, len(headers))

	for i, h := range headers {
		_headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(_headers[i])
	}
	beignHash := [32]byte(_headers[0][4:36])

	unitCcs, err := operations.ReadCcs(unitCcsFile)
	assert.NoError(err)

	unitVk, err := operations.ReadVk(unitVkFile)
	assert.NoError(err)

	unitVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](unitVk)
	assert.NoError(err)

	circuit := NewBlockHeaderRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitCcs,
		unitVkFpBytes,
	)

	firstProof, err := operations.ReadProof(firstProofFile)
	assert.NoError(err)

	secondProof, err := operations.ReadProof(secondProofFile)
	assert.NoError(err)

	firstWitness, err := operations.ReadWitness(firstWitnessFile)
	assert.NoError(err)

	secondWitness, err := operations.ReadWitness(secondWitnessFile)
	assert.NoError(err)

	recursiveVk, err := operations.ReadVk(recursiveVkFile)
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	assignment, err := NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		recursiveVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		beignHash,
		hashes[1],
		hashes[2],
	)

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBlockHeaderRecursiveCircuit_Recursive_0_3_Plonk(t *testing.T) {
	assert := test.NewAssert(t)

	firstProofFile := "../testdata/block_header_recursive_0_2.proof"
	firstWitnessFile := "../testdata/block_header_recursive_0_2.wtns"
	secondProofFile := "../testdata/block_header_unit_2_3.proof"
	secondWitnessFile := "../testdata/block_header_unit_2_3.wtns"

	_headers := make([][]byte, len(headers))
	hashes := make([][32]byte, len(headers))

	for i, h := range headers {
		_headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(_headers[i])
	}
	beignHash := [32]byte(_headers[0][4:36])

	unitVk, err := operations.ReadVk(unitVkFile)
	assert.NoError(err)

	firstProof, err := operations.ReadProof(firstProofFile)
	assert.NoError(err)

	secondProof, err := operations.ReadProof(secondProofFile)
	assert.NoError(err)

	firstWitness, err := operations.ReadWitness(firstWitnessFile)
	assert.NoError(err)

	secondWitness, err := operations.ReadWitness(secondWitnessFile)
	assert.NoError(err)

	recursiveVk, err := operations.ReadVk(recursiveVkFile)
	assert.NoError(err)

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	assert.NoError(err)

	recursiveVkFp := utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	assignment, err := NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		recursiveVk, unitVk,
		firstProof, secondProof,
		firstWitness, secondWitness,
		recursiveVkFp,
		beignHash,
		hashes[1],
		hashes[2],
	)

	recursiveCcs, err := operations.ReadCcs(recursiveCcsFile)
	assert.NoError(err)

	recursivePk, err := operations.ReadPk(recursivePkFile)
	assert.NoError(err)

	proof, witness, err := operations.PlonkProve(recursiveCcs, recursivePk, assignment, false)
	assert.NoError(err)

	err = operations.PlonkVerify(recursiveVk, proof, witness, false)
	assert.NoError(err)

	proofFile := "../testdata/block_header_recursive_0_3.proof"
	witnessFile := "../testdata/block_header_recursive_0_3.wtns"

	err = operations.WriteProof(proof, proofFile)
	assert.NoError(err)

	err = operations.WriteWitness(witness, witnessFile)
	assert.NoError(err)
}
