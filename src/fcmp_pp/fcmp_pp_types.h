// Copyright (c) 2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <map>
#include <memory>
#include <type_traits>
#include <variant>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "fcmp_pp_crypto.h"
#include "fcmp_pp_rust/fcmp++.h"
#include "serialization/keyvalue_serialization.h"

// TODO: consolidate more FCMP++ types into this file

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Rust types
//----------------------------------------------------------------------------------------------------------------------
using SeleneScalar = ::SeleneScalar;
static_assert(sizeof(SeleneScalar) == 32, "unexpected size of selene scalar");
using HeliosScalar = ::HeliosScalar;
static_assert(sizeof(HeliosScalar) == 32, "unexpected size of helios scalar");
//----------------------------------------------------------------------------------------------------------------------
struct SeleneT final
{
    using Scalar       = SeleneScalar;
    using Point        = ::SelenePoint;
    using Chunk        = ::SeleneScalarSlice;
    using CycleScalar  = HeliosScalar;
    using ScalarChunks = ::SeleneScalarChunks;
};
//----------------------------------------------------------------------------------------------------------------------
struct HeliosT final
{
    using Scalar       = HeliosScalar;
    using Point        = ::HeliosPoint;
    using Chunk        = ::HeliosScalarSlice;
    using CycleScalar  = SeleneScalar;
    using ScalarChunks = ::HeliosScalarChunks;
};
//----------------------------------------------------------------------------------------------------------------------
using OutputTuple = ::OutputTuple;
using OutputChunk = ::OutputSlice;
//----------------------------------------------------------------------------------------------------------------------
OutputTuple output_tuple_from_bytes(const crypto::ec_point &O, const crypto::ec_point &I, const crypto::ec_point &C);
//----------------------------------------------------------------------------------------------------------------------
// Define FCMP++ prove/verify C++ type here so it can be used in FFI types
using FcmpPpProof = std::vector<uint8_t>;
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// FFI types
//----------------------------------------------------------------------------------------------------------------------
// FFI types instantiated on the Rust side must be destroyed back on the Rust side. We wrap them in a unique ptr with a
// custom deleter that calls the respective Rust destroy fn.
#define DEFINE_FCMP_FFI_TYPE(raw_t, cpp_fn)                                      \
    struct raw_t##Deleter { void operator()(raw_t##Unsafe *p) const noexcept; }; \
    using raw_t = std::unique_ptr<raw_t##Unsafe, raw_t##Deleter>;                \
    raw_t cpp_fn;

// Macro to instantiate an FFI-compatible slice from a vector of FCMP FFI type. Instantiates a vector in local scope
// so it remains in scope while the slice points to it, making sure memory addresses remain contiguous. The slice is
// only usable within local scope, hence "TEMP".
#define MAKE_TEMP_FFI_SLICE(raw_t, vec, slice_name)                              \
    std::vector<const raw_t##Unsafe *> raw_t##Vector;                            \
    raw_t##Vector.reserve(vec.size());                                           \
    for (const raw_t &elem : vec)                                                \
        raw_t##Vector.push_back(elem.get());                                     \
    ::raw_t##SliceUnsafe slice_name{raw_t##Vector.data(), raw_t##Vector.size()};

DEFINE_FCMP_FFI_TYPE(HeliosBranchBlind, gen_helios_branch_blind());
DEFINE_FCMP_FFI_TYPE(SeleneBranchBlind, gen_selene_branch_blind());

DEFINE_FCMP_FFI_TYPE(BlindedOBlind, blind_o_blind(const SeleneScalar &));
DEFINE_FCMP_FFI_TYPE(BlindedIBlind, blind_i_blind(const SeleneScalar &));
DEFINE_FCMP_FFI_TYPE(BlindedIBlindBlind, blind_i_blind_blind(const SeleneScalar &));
DEFINE_FCMP_FFI_TYPE(BlindedCBlind, blind_c_blind(const SeleneScalar &));

DEFINE_FCMP_FFI_TYPE(OutputBlinds,
    output_blinds_new(const BlindedOBlind &, const BlindedIBlind &, const BlindedIBlindBlind &, const BlindedCBlind &));

// Use a shared pointer so we can reference the same underlying tree root in multiple places
using TreeRootShared = std::shared_ptr<TreeRootUnsafe>;
TreeRootShared helios_tree_root(const HeliosPoint &);
TreeRootShared selene_tree_root(const SelenePoint &);

DEFINE_FCMP_FFI_TYPE(Path,
    path_new(const OutputChunk &, std::size_t, const HeliosT::ScalarChunks &, const SeleneT::ScalarChunks &));

DEFINE_FCMP_FFI_TYPE(FcmpPpProveMembershipInput,
    fcmp_pp_prove_input_new(const Path &,
        const OutputBlinds &,
        const std::vector<SeleneBranchBlind> &,
        const std::vector<HeliosBranchBlind> &));

DEFINE_FCMP_FFI_TYPE(FcmpPpVerifyInput,
    fcmp_pp_verify_input_new(const crypto::hash &signable_tx_hash,
        const fcmp_pp::FcmpPpProof &fcmp_pp_proof,
        const std::size_t n_tree_layers,
        const fcmp_pp::TreeRootShared &tree_root,
        const std::vector<crypto::ec_point> &pseudo_outs,
        const std::vector<crypto::key_image> &key_images));
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// C++ types
//----------------------------------------------------------------------------------------------------------------------
//   Curve trees types
//----------------------------------------------------------------------------------------------------------------------
// Output pub key and commitment, ready to be converted to a leaf tuple
// - From {output_pubkey,commitment} -> {O,C} -> {O.x,O.y,I.x,I.y,C.x,C.y}
// - Output pairs do NOT necessarily have torsion cleared. We need the output pubkey as it exists in the chain in order
//   to derive the correct I (when deriving {O.x,O.y,I.x,I.y,C.x,C.y}). Torsion clearing O before deriving I from O
//   would enable spending a torsioned output once before FCMP++ fork and again with a different key image via FCMP++.
template<typename T>
struct OutputPairTemplate
{
    crypto::public_key output_pubkey;
    // Uses the ec_point type to avoid a circular dep to ringct/rctTypes.h, and to differentiate from output_pubkey
    crypto::ec_point commitment;

    OutputPairTemplate(const crypto::public_key &_output_pubkey, const crypto::ec_point &_commitment):
        output_pubkey(_output_pubkey),
        commitment(_commitment)
    {};

    OutputPairTemplate():
        output_pubkey{},
        commitment{}
    {};

    bool operator==(const OutputPairTemplate &other) const
    {
        return output_pubkey == other.output_pubkey
            && commitment == other.commitment;
    }
};

// May have torsion, use biased key image generator for I
struct LegacyOutputPair : public OutputPairTemplate<LegacyOutputPair>{};
// No torsion, use unbiased key image generator for I
struct CarrotOutputPairV1 : public OutputPairTemplate<CarrotOutputPairV1>{};

static_assert(sizeof(LegacyOutputPair)   == (32+32), "sizeof LegacyOutputPair unexpected");
static_assert(sizeof(CarrotOutputPairV1) == (32+32), "sizeof CarrotOutputPairV1 unexpected");

static_assert(std::has_unique_object_representations_v<LegacyOutputPair>);
static_assert(std::has_unique_object_representations_v<CarrotOutputPairV1>);

using OutputPair = std::variant<LegacyOutputPair, CarrotOutputPairV1>;

const crypto::public_key &output_pubkey_cref(const OutputPair &output_pair);
const crypto::ec_point &commitment_cref(const OutputPair &output_pair);

bool output_checked_for_torsion(const OutputPair &output_pair);
bool use_biased_hash_to_point(const OutputPair &output_pair);

// Wrapper for outputs with context to insert the output into the FCMP++ curve tree
struct UnifiedOutput final
{
    // Output's unique id in the chain, used to insert the output in the tree in the order it entered the chain
    uint64_t unified_id{0};
    OutputPair output_pair;

    bool operator==(const UnifiedOutput &other) const
    {
        return unified_id == other.unified_id && output_pair == other.output_pair;
    }

    // TODO: move to fcmp_pp_serialization.h
    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(unified_id)
        KV_SERIALIZE(output_pair)
    END_KV_SERIALIZE_MAP()
};

#define SIZEOF_SERIALIZED_UNIFIED_OUTPUT 73 // 8+1+32+32

using OutsByLastLockedBlock = std::unordered_map<uint64_t, std::vector<UnifiedOutput>>;

// A layer of contiguous hashes starting from a specific start_idx in the tree
template<typename C>
struct LayerExtension final
{
    uint64_t                       start_idx{0};
    bool                           update_existing_last_hash;
    std::vector<typename C::Point> hashes;
};

// Useful metadata for growing a layer
struct GrowLayerInstructions final
{
    // The max chunk width of children used to hash into a parent
    std::size_t parent_chunk_width;

    // Total parents refers to the total number of hashes of chunks of children
    uint64_t old_total_parents;
    uint64_t new_total_parents;

    // When updating the tree, we use this boolean to know when we'll need to use the tree's existing old root in order
    // to set a new layer after that root
    // - We'll need to be sure the old root gets hashed when setting the next layer
    bool setting_next_layer_after_old_root;
    // When the last child in the child layer changes, we'll need to use its old value to update its parent hash
    bool need_old_last_child;
    // When the last parent in the layer changes, we'll need to use its old value to update itself
    bool need_old_last_parent;

    // The first chunk that needs to be updated's first child's offset within that chunk
    std::size_t start_offset;
    // The parent's starting index in the layer
    uint64_t next_parent_start_index;
};

// Struct composed of ec elems needed to get a full-fledged leaf tuple
struct PreLeafTuple final
{
    fcmp_pp::EdDerivatives O_derivatives;
    fcmp_pp::EdDerivatives I_derivatives;
    fcmp_pp::EdDerivatives C_derivatives;
};

struct ChunkBytes final
{
    std::vector<crypto::ec_point> chunk_bytes;

    bool operator==(const ChunkBytes &other) const { return chunk_bytes == other.chunk_bytes; }

    // TODO: move to fcmp_pp_serialization.h
    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(chunk_bytes)
    END_KV_SERIALIZE_MAP()
};

struct PathBytes final
{
    std::vector<UnifiedOutput> leaves;
    std::vector<ChunkBytes> layer_chunks;

    bool operator==(const PathBytes &other) const {return leaves == other.leaves && layer_chunks == other.layer_chunks;}

    // TODO: move to fcmp_pp_serialization.h
    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(leaves)
        KV_SERIALIZE(layer_chunks)
    END_KV_SERIALIZE_MAP()
};

// The indexes in the tree of a leaf's path elems containing whole chunks at each layer
// - leaf_range refers to a complete chunk of leaves
struct PathIndexes final
{
    using StartIdx = uint64_t;
    using EndIdxExclusive = uint64_t;
    using Range = std::pair<StartIdx, EndIdxExclusive>;

    Range leaf_range;
    std::vector<Range> layers;
};

// Tuple that composes a single leaf in the tree
template<typename C>
struct LeafTupleT final
{
    // Output ed25519 point wei x and y coordinates
    typename C::Scalar O_x;
    typename C::Scalar O_y;
    // Key image generator wei x and y coordinates
    typename C::Scalar I_x;
    typename C::Scalar I_y;
    // Commitment wei x and y coordinates
    typename C::Scalar C_x;
    typename C::Scalar C_y;
};

static const std::size_t LEAF_TUPLE_POINTS = 3;
static constexpr std::size_t LEAF_TUPLE_SIZE = LEAF_TUPLE_POINTS * 2;

// Contiguous leaves in the tree, starting at a specified start_idx in the leaf layer
struct Leaves final
{
    // Starting leaf tuple index in the leaf layer
    uint64_t                   start_leaf_tuple_idx{0};
    // Contiguous leaves in a tree that start at the start_idx
    std::vector<UnifiedOutput> tuples;
};

// A struct useful to extend an existing tree
// - layers alternate between C1 and C2
// - c1_layer_extensions[0] is first layer after leaves, then c2_layer_extensions[0], c1_layer_extensions[1], etc
template <typename C1, typename C2>
struct TreeExtensionT final
{
    Leaves                          leaves;
    std::vector<LayerExtension<C1>> c1_layer_extensions;
    std::vector<LayerExtension<C2>> c2_layer_extensions;
};

// Last hashes from each layer in the tree
// - layers alternate between C1 and C2
// - c1_last_hashes[0] refers to the layer after leaves, then c2_last_hashes[0], then c1_last_hashes[1], etc
template <typename C1, typename C2>
struct LastHashesT final
{
    std::vector<typename C1::Point> c1_last_hashes;
    std::vector<typename C2::Point> c2_last_hashes;
};

// A path in the tree containing whole chunks at each layer
// - leaves contain a complete chunk of leaves, encoded as compressed ed25519 points
// - c1_layers[0] refers to the chunk of elems in the tree in the layer after leaves. The hash of the chunk of
//   leaves is 1 member of the c1_layers[0] chunk. The rest of c1_layers[0] is the chunk of elems that hash is in.
// - layers alternate between C1 and C2
// - c2_layers[0] refers to the chunk of elems in the tree in the layer after c1_layers[0]. The hash of the chunk
//   of c1_layers[0] is 1 member of the c2_layers[0] chunk. The rest of c2_layers[0] is the chunk of elems that hash
//   is in.
// - c1_layers[1] refers to the chunk of elems in the tree in the layer after c2_layers[0] etc.
template <typename C1, typename C2>
struct PathT final
{
    std::vector<OutputTuple> leaves;
    std::vector<std::vector<typename C1::Point>> c1_layers;
    std::vector<std::vector<typename C2::Point>> c2_layers;

    void clear()
    {
        leaves.clear();
        c1_layers.clear();
        c2_layers.clear();
    }

    bool empty() const { return leaves.empty() && c1_layers.empty() && c2_layers.empty(); }
};

// Contains minimum path elems necessary for multiple paths (e.g. only contains the root once)
template <typename C1, typename C2>
struct ConsolidatedPathsT final
{
    std::unordered_map<uint64_t, std::vector<OutputTuple>> leaves_by_chunk_idx;
    std::vector<std::unordered_map<uint64_t, std::vector<typename C1::Point>>> c1_layers;
    std::vector<std::unordered_map<uint64_t, std::vector<typename C2::Point>>> c2_layers;
};

// A path ready to be used to construct an FCMP++ proof
template <typename C1, typename C2>
struct PathForProofT final
{
    std::vector<OutputTuple> leaves;
    std::size_t output_idx;
    std::vector<std::vector<typename C2::Scalar>> c2_scalar_chunks;
    std::vector<std::vector<typename C1::Scalar>> c1_scalar_chunks;
};
//----------------------------------------------------------------------------------------------------------------------
//   FCMP++ prove/verify types
//----------------------------------------------------------------------------------------------------------------------
// Byte buffer containing the fcmp++ proof
using FcmpPpSalProof = std::vector<uint8_t>;
using FcmpMembershipProof = std::vector<uint8_t>;

struct ProofInput final
{
    Path path;
    OutputBlinds output_blinds;
    std::vector<SeleneBranchBlind> selene_branch_blinds;
    std::vector<HeliosBranchBlind> helios_branch_blinds;
};

struct ProofParams final
{
    uint64_t reference_block;
    std::vector<ProofInput> proof_inputs;
};

struct FcmpVerifyHelperData final
{
    TreeRootShared tree_root;
    std::vector<crypto::key_image> key_images;
};

// Serialize types into a single byte buffer
FcmpPpProof fcmp_pp_proof_from_parts_v1(const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
    const std::vector<FcmpPpSalProof> &sal_proofs,
    const FcmpMembershipProof &membership_proof,
    const std::uint8_t n_tree_layers);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp

inline bool operator==(const fcmp_pp::OutputTuple &a, const fcmp_pp::OutputTuple &b)
{
    return
        (memcmp(a.O, b.O, sizeof(a.O)) == 0) &&
        (memcmp(a.I, b.I, sizeof(a.I)) == 0) &&
        (memcmp(a.C, b.C, sizeof(a.C)) == 0);
}
