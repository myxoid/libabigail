// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020 Google, Inc.
//
// Author: Giuliano Procida

#ifndef __ABG_SCC_H__
#define __ABG_SCC_H__

#include <cassert>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace abigail
{

/*
 * This is a streamlined Strongly-Connected Component finder for use with
 * procedurally generated or explored graphs, where the nodes and edges are not
 * known a priori.
 *
 * REQUIREMENTS
 *
 * The Node type must be copyable and the user must supply a well-behaved
 * comparison function (allowing arbitrary data to accompany each node).
 *
 * The user code must take the form of a Depth First Search which can be
 * repeatedly invoked on unvisited nodes until the whole graph has been
 * traversed.
 *
 * The user code must ensure that nodes are not revisited once they have been
 * assigned to an SCC. The finder does not maintain any state for such nodes.
 *
 * GUARANTEES
 *
 * Each node will be examined exactly once.
 *
 * The SCCs will be presented in a topological order, leaves first.
 *
 * Note that within each SCC, nodes will be presented in DFS traversal order,
 * roots first. However, this is just an implemention detail, not a guarantee.
 *
 * USAGE
 *
 * Before examining a node, check it's not been visited already and then call
 * Open. If the node is already "open" (i.e., is already waiting to be assigned
 * to an SCC), this will return an empty optional value and the node should not
 * be examined. If Open succeeds, a numerical node handle will be returned and
 * the node will be recorded as waiting to be assigned to an SCC.
 *
 * Now examine the node, making recursive calls to follow edges to other nodes.
 *
 * Once the examination is done, call Close, passing in the handle and
 * optionally a function to update data associated with the node. If the node
 * has been identified as the "root" of an SCC, the whole SCC will be returned
 * as a vector of nodes. If any processing needs to be done (such as recording
 * the nodes as visited), this should be done now. Otherwise, an empty vector
 * will be returned.
 */
template <typename Node> class SCC
{
public:
  explicit SCC(std::function<bool(const Node&, const Node&)> cmp) : cmp_(cmp)
  {
  }
  ~SCC()
  {
    assert(open_.empty());
    assert(root_index_.empty());
  }

  std::optional<size_t>
  Open(const Node& node)
  {
    for (size_t ix = 0; ix < open_.size(); ++ix)
      {
	const auto& other = open_[ix];
	// node == other?
	if (!cmp_(node, other) && !cmp_(other, node))
	  {
	    // Pop indices to nodes which cannot be the root of their SCC.
	    while (root_index_.back() > ix)
	      root_index_.pop_back();
	    return {};
	  }
      }
    // Unvisited, mark node as open and record root index.
    auto ix = open_.size();
    open_.push_back(node);
    root_index_.push_back(ix);
    return ix;
  }

  std::vector<Node>
  Close(
      size_t ix, std::function<void(Node&)> update = [](Node&) {})
  {
    std::vector<Node> scc;
    assert(ix < open_.size());
    update(open_[ix]);
    if (ix == root_index_.back())
      {
	// Close SCC.
	root_index_.pop_back();
	std::move(open_.begin() + ix, open_.end(), std::back_inserter(scc));
	open_.resize(ix);
      }
    return scc;
  }

private:
  std::function<bool(const Node&, const Node&)> cmp_;
  std::vector<Node> open_;
  std::vector<size_t> root_index_;
};

} // namespace abigail

#endif // __ABG_SCC_H__
