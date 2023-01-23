package state_native

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math"
	"math/bits"

	"github.com/prysmaticlabs/prysm/v3/beacon-chain/state/fieldtrie"
	nativetypes "github.com/prysmaticlabs/prysm/v3/beacon-chain/state/state-native/types"
	"github.com/prysmaticlabs/prysm/v3/encoding/bytesutil"
	"github.com/prysmaticlabs/prysm/v3/runtime/version"
)

const (
	finalizedRootIndex  = uint64(105)    // Precomputed value.
	firstBlockRootIndex = uint64(303104) // Precomputed value.
)

// FinalizedRootGeneralizedIndex for the beacon state.
func FinalizedRootGeneralizedIndex() uint64 {
	return finalizedRootIndex
}

// CurrentSyncCommitteeGeneralizedIndex for the beacon state.
func (b *BeaconState) CurrentSyncCommitteeGeneralizedIndex() (uint64, error) {
	if b.version == version.Phase0 {
		return 0, errNotSupported("CurrentSyncCommitteeGeneralizedIndex", b.version)
	}

	return uint64(nativetypes.CurrentSyncCommittee.RealPosition()), nil
}

// NextSyncCommitteeGeneralizedIndex for the beacon state.
func (b *BeaconState) NextSyncCommitteeGeneralizedIndex() (uint64, error) {
	if b.version == version.Phase0 {
		return 0, errNotSupported("NextSyncCommitteeGeneralizedIndex", b.version)
	}

	return uint64(nativetypes.NextSyncCommittee.RealPosition()), nil
}

// CurrentSyncCommitteeProof from the state's Merkle trie representation.
func (b *BeaconState) CurrentSyncCommitteeProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("CurrentSyncCommitteeProof", b.version)
	}

	// In case the Merkle layers of the trie are not populated, we need
	// to perform some initialization.
	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	// Our beacon state uses a "dirty" fields pattern which requires us to
	// recompute branches of the Merkle layers that are marked as dirty.
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	return fieldtrie.ProofFromMerkleLayers(b.merkleLayers, nativetypes.CurrentSyncCommittee.RealPosition()), nil
}

// NextSyncCommitteeProof from the state's Merkle trie representation.
func (b *BeaconState) NextSyncCommitteeProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("NextSyncCommitteeProof", b.version)
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	return fieldtrie.ProofFromMerkleLayers(b.merkleLayers, nativetypes.NextSyncCommittee.RealPosition()), nil
}

// FinalizedRootProof crafts a Merkle proof for the finalized root
// contained within the finalized checkpoint of a beacon state.
func (b *BeaconState) FinalizedRootProof(ctx context.Context) ([][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return nil, errNotSupported("FinalizedRootProof", b.version)
	}

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return nil, err
	}
	cpt := b.finalizedCheckpointVal()
	// The epoch field of a finalized checkpoint is the neighbor
	// index of the finalized root field in its Merkle tree representation
	// of the checkpoint. This neighbor is the first element added to the proof.
	epochBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(epochBuf, uint64(cpt.Epoch))
	epochRoot := bytesutil.ToBytes32(epochBuf)
	proof := make([][]byte, 0)
	proof = append(proof, epochRoot[:])
	branch := fieldtrie.ProofFromMerkleLayers(b.merkleLayers, nativetypes.FinalizedCheckpoint.RealPosition())
	proof = append(proof, branch...)
	return proof, nil
}

func (b *BeaconState) BlockRootProof(ctx context.Context) ([32]byte, [][]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if err := b.initializeMerkleLayers(ctx); err != nil {
		return [32]byte{}, nil, err
	}
	if err := b.recomputeDirtyFields(ctx); err != nil {
		return [32]byte{}, nil, err
	}

	proof := make([][]byte, 0)
	generalizedIndex := nativetypes.BlockRoots.RealPosition()

	leaf, err := b.blockRoots.HashTreeRoot()
	if err != nil {
		return [32]byte{}, nil, err
	}

	branch := fieldtrie.ProofFromMerkleLayers(b.merkleLayers, generalizedIndex)
	proof = append(proof, branch...)
	return leaf, proof, nil
}

func (b *BeaconState) BlockRootProofAtIndex(blockIndex int) ([32]byte, [][]byte, [32]byte, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	err := b.buildBlockRoots()
	if err != nil {
		return [32]byte{}, nil, [32]byte{}, err
	}

	layers := b.stateFieldLeaves[5].GetLayers()

	leaves := layers[0]

	convertedLeaves := make([][]byte, len(leaves))

	for _, leaf := range leaves {
		convertedLeaves = append(convertedLeaves, leaf[:])
	}

	if err := b.initializeMerkleLayersBlockRoots(convertedLeaves); err != nil {
		return [32]byte{}, nil, [32]byte{}, err
	}

	proof := make([][]byte, 0)

	//generalizedIndex := blockIndex + int(firstBlockRootIndex)

	blockRootAtIndex := b.blockRoots[blockIndex]

	fmt.Printf("blockRootAtIndex: %s\n", common.BytesToHash(blockRootAtIndex[:]))
	//fmt.Printf("generalizedIndex: %d\n", generalizedIndex)

	//index := getSubTreeIndex(generalizedIndex)
	//depth := floorLog2(generalizedIndex)

	//fmt.Printf("index: %d\n", index)
	//fmt.Printf("depth: %d\n", depth)

	branch := fieldtrie.ProofFromMerkleLayers(b.merkleLayers, blockIndex)
	proof = append(proof, branch...)
	root, err := b.blockRoots.HashTreeRoot()
	if err != nil {
		return [32]byte{}, nil, [32]byte{}, err
	}

	return blockRootAtIndex, proof, root, nil
}

func floorLog2(value int) int {
	return bits.Len(uint(value)) - 1
}

func getSubTreeIndex(index int) int {
	return index % int(math.Pow(2, float64(floorLog2(index))))
}
