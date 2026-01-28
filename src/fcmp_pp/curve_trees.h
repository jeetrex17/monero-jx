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

#include "crypto/crypto.h"
#include "fcmp_pp_types.h"
#include "misc_log_ex.h"
#include "tower_cycle.h"

#include <memory>
#include <vector>


namespace fcmp_pp
{
namespace curve_trees
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Hash a chunk of new children
template<typename C>
typename C::Point get_new_parent(const std::unique_ptr<C> &curve, const typename C::Chunk &new_children);
//----------------------------------------------------------------------------------------------------------------------
OutputTuple output_to_tuple(const OutputPair &output_pair, bool use_fast_check = false);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// This class is useful to help update the curve trees merkle tree without needing to keep the entire tree in memory
// - It requires instantiation with the C1 and C2 curve classes and widths, hardening the tree structure
// - It ties the C1 curve in the tree to the leaf layer (the leaf layer is composed of C1 scalars)
template<typename C1, typename C2>
class CurveTrees
{
public:
    CurveTrees(std::unique_ptr<C1> &&c1,
        std::unique_ptr<C2> &&c2,
        const std::size_t c1_width,
        const std::size_t c2_width):
            m_c1{std::move(c1)},
            m_c2{std::move(c2)},
            m_c1_width{c1_width},
            m_c2_width{c2_width},
            m_leaf_layer_chunk_width{LEAF_TUPLE_SIZE * c1_width}
    {
        assert(c1_width > 0);
        assert(c2_width > 0);
    };

//member structs
public:
    using LeafTuple = LeafTupleT<C1>;
    static_assert(sizeof(LeafTuple) == (sizeof(typename C1::Scalar) * LEAF_TUPLE_SIZE), "unexpected LeafTuple size");

    using TreeExtension     = TreeExtensionT<C1, C2>;
    using LastHashes        = LastHashesT<C1, C2>;
    using Path              = PathT<C1, C2>;
    using ConsolidatedPaths = ConsolidatedPathsT<C1, C2>;
    using PathForProof      = PathForProofT<C1, C2>;

//member functions
public:
    // Convert output pairs into leaf tuples, from {output pubkey,commitment} -> {O,C} -> {O.x,O.y,I.x,I.y,C.x,C.y}
    LeafTuple leaf_tuple(const OutputPair &output_pair) const;

    // Flatten leaves
    // From: [{O.x,O.y,I.x,I.y,C.x,C.y},{O.x,O.y,I.x,I.y,C.x,C.y},...]
    // To: [O.x,O.y,I.x,I.y,C.x,C.y,O.x,O.y,I.x,I.y,C.x,C.y...]
    std::vector<typename C1::Scalar> flatten_leaves(std::vector<LeafTuple> &&leaves) const;

    // Take in the existing number of leaf tuples and the existing last hash in each layer in the tree, as well as new
    // outputs to add to the tree, and return a tree extension struct that can be used to extend a tree
    TreeExtension get_tree_extension(const uint64_t old_n_leaf_tuples,
        const LastHashes &existing_last_hashes,
        std::vector<std::vector<UnifiedOutput>> &&new_outputs,
        const bool use_fast_torsion_check = false);

    // Calculate the number of elems in each layer of the tree based on the number of leaf tuples
    std::vector<uint64_t> n_elems_per_layer(const uint64_t n_leaf_tuples) const;

    // Calculate how many layers in the tree there are based on the number of leaf tuples
    std::size_t n_layers(const uint64_t n_leaf_tuples) const;

    // Get path indexes for the provided leaf tuple
    // - Returns empty path indexes if leaf is not in the tree (if n_leaf_tuples <= leaf_tuple_idx)
    PathIndexes get_path_indexes(const uint64_t n_leaf_tuples, const uint64_t leaf_tuple_idx) const;

    // Get child chunk indexes for the provided leaf tuple
    // - Returns empty if leaf is not in the tree (if n_leaf_tuples <= leaf_tuple_idx)
    std::vector<uint64_t> get_child_chunk_indexes(const uint64_t n_leaf_tuples, const uint64_t leaf_tuple_idx) const;

    LastHashes tree_edge_to_last_hashes(const std::vector<crypto::ec_point> &tree_edge_to_last_hashes) const;

    // Audit the provided path
    bool audit_path(const Path &path, const OutputPair &output, const uint64_t n_leaf_tuples_in_tree) const;

    TreeRootShared get_tree_root_from_bytes(const std::size_t n_layers, const crypto::ec_point &tree_root) const;

    Path path_bytes_to_path(const PathBytes &path_bytes) const;

    PathForProof path_for_proof(const Path &path, const OutputTuple &output_tuple) const;

    std::vector<crypto::ec_point> calc_hashes_from_path(const Path &path, const bool replace_last_hash = false) const;

    TreeExtension path_to_tree_extension(const PathBytes &path_bytes, const PathIndexes &path_idxs) const;

    ConsolidatedPaths get_dummy_paths(const std::vector<fcmp_pp::UnifiedOutput> &outputs, uint8_t n_layers) const;

    Path get_single_dummy_path(const ConsolidatedPaths &dummy_paths,
        const uint64_t n_leaf_tuples,
        const uint64_t leaf_tuple_idx) const;
private:
    // Multithreaded helper function to convert outputs to leaf tuples and set leaves on tree extension
    void set_valid_leaves(
        std::vector<typename C1::Scalar> &flattened_leaves_out,
        std::vector<UnifiedOutput> &tuples_out,
        std::vector<UnifiedOutput> &&new_outputs,
        const bool use_fast_torsion_check = false);

    // Helper function used to set the next layer extension used to grow the next layer in the tree
    // - for example, if we just grew the parent layer after the leaf layer, the "next layer" would be the grandparent
    //   layer of the leaf layer
    GrowLayerInstructions set_next_layer_extension(
        const GrowLayerInstructions &prev_layer_instructions,
        const bool parent_is_c1,
        const LastHashes &last_hashes,
        std::size_t &c1_last_idx_inout,
        std::size_t &c2_last_idx_inout,
        TreeExtension &tree_extension_inout) const;

//private state
private:
    uint64_t m_set_valid_leaves_ms{0};
    uint64_t m_get_selene_scalars_ms{0};
    uint64_t m_batch_invert_ms{0};
    uint64_t m_collect_derivatives_ms{0};
    uint64_t m_convert_valid_leaves_ms{0};

    uint64_t m_sorting_outputs_ms{0};
    uint64_t m_hash_leaves_ms{0};
    uint64_t m_hash_layers_ms{0};

//public member variables
public:
    // The curve interfaces
    const std::unique_ptr<C1> m_c1;
    const std::unique_ptr<C2> m_c2;

    // The leaf layer has a distinct chunk width than the other layers
    const std::size_t m_leaf_layer_chunk_width;

    // The chunk widths of the layers in the tree tied to each curve
    const std::size_t m_c1_width;
    const std::size_t m_c2_width;
};
//----------------------------------------------------------------------------------------------------------------------
using Selene       = tower_cycle::Selene;
using Helios       = tower_cycle::Helios;
using CurveTreesV1 = CurveTrees<Selene, Helios>;

// https://github.com/kayabaNerve/fcmp-plus-plus/blob
//  /b2742e86f3d18155fd34dd1ed69cb8f79b900fce/crypto/fcmps/src/tests.rs#L81-L82
const std::size_t SELENE_CHUNK_WIDTH = 38;
const std::size_t HELIOS_CHUNK_WIDTH = 18;

std::shared_ptr<CurveTreesV1> curve_trees_v1(
    const std::size_t selene_chunk_width = SELENE_CHUNK_WIDTH,
    const std::size_t helios_chunk_width = HELIOS_CHUNK_WIDTH);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
} //namespace curve_trees
} //namespace fcmp_pp
