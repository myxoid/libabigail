// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020 Google, Inc.
//
// Author: Giuliano Procida

#include <algorithm>
#include <array>
#include <cmath>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <vector>

#include "lib/catch.hpp"

#include "abg-scc.h"

namespace Test
{

using abigail::SCC;

// Nodes are [0, N), the sets are the out-edges.
typedef std::vector<std::set<size_t>> Graph;

std::ostream&
operator<<(std::ostream& os, const Graph& g)
{
  for (size_t i = 0; i < g.size(); ++i)
    {
      os << i << ':';
      for (auto o : g[i])
	os << ' ' << o;
      os << '\n';
    }
  return os;
}

template <typename G>
Graph
invent(size_t n, G& gen)
{
  Graph graph(n);
  std::uniform_int_distribution<int> toss(0, 1);
  for (auto& node : graph)
    {
      for (size_t o = 0; o < n; ++o)
	{
	  if (toss(gen))
	    node.insert(o);
	}
    }
  return graph;
}

// Generate a graph g' where a -> b iff a and b are strongly connected in g.
Graph
symmetric_subset_of_reflexive_transitive_closure(Graph g)
{
  const size_t n = g.size();
  // transitive closure using Floyd-Warshall
  for (size_t o = 0; o < n; ++o)
    g[o].insert(o);
  for (size_t k = 0; k < n; ++k)
    {
      for (size_t i = 0; i < n; ++i)
	{
	  for (size_t j = 0; j < n; ++j)
	    {
	      if (!g[i].count(j) && g[i].count(k) && g[k].count(j))
		g[i].insert(j);
	    }
	}
    }
  // now a -> b iff a has path to b in g
  for (size_t i = 0; i < n; ++i)
    {
      for (size_t j = i + 1; j < n; ++j)
	{
	  // discard a -> b if not b -> a and vice versa
	  auto ij = g[i].count(j);
	  auto ji = g[j].count(i);
	  if (ij < ji)
	    g[j].erase(i);
	  if (ji < ij)
	    g[i].erase(j);
	}
    }
  // now have a -> b iff a has path to b and b has path to a in g
  return g;
}

// Generate a graph where a -> b iff a and b are in the same SCC.
Graph
scc_strong_connectivity(const std::vector<std::set<size_t>>& sccs)
{
  size_t n = 0;
  std::map<size_t, const std::set<size_t>*> edges;
  for (const auto& scc : sccs)
    {
      for (auto o : scc)
	{
	  if (o >= n)
	    n = o + 1;
	  edges[o] = &scc;
	}
    }
  Graph g(n);
  for (size_t o = 0; o < n; ++o)
    g[o] = *edges[o];
  return g;
}

void
dfs(std::set<size_t>& visited,
    SCC<size_t>& scc,
    const Graph& g,
    size_t node,
    std::vector<std::set<size_t>>& sccs)
{
  if (visited.count(node))
    return;
  auto handle = scc.Open(node);
  if (!handle)
    return;
  for (auto o : g[node])
    dfs(visited, scc, g, o, sccs);
  auto nodes = scc.Close(handle.value());
  if (!nodes.empty())
    {
      std::set<size_t> scc_set;
      for (auto o : nodes)
	{
	  CHECK(visited.insert(o).second);
	  CHECK(scc_set.insert(o).second);
	}
      sccs.push_back(scc_set);
    }
}

void
process(const Graph& g)
{
  const size_t n = g.size();

  // find SCCs
  std::set<size_t> visited;
  SCC<size_t> scc{std::less<size_t>()};
  std::vector<std::set<size_t>> sccs;
  for (size_t o = 0; o < n; ++o)
    dfs(visited, scc, g, o, sccs);

  // check partition and topological order properties
  std::set<size_t> seen;
  for (const auto& nodes : sccs)
    {
      CHECK(!nodes.empty());
      for (auto node : nodes)
	{
	  // value in range [0, n)
	  CHECK(node < n);
	  // value seen at most once
	  CHECK(seen.insert(node).second);
	}
      for (auto node : nodes)
	{
	  for (auto o : g[node])
	    {
	      // edges point to nodes in this or earlier SCCs
	      CHECK(seen.count(o));
	    }
	}
    }
  // exactly n values seen
  CHECK(seen.size() == n);

  // check strong connectivity
  auto g_scc_closure = scc_strong_connectivity(sccs);
  auto g_closure = symmetric_subset_of_reflexive_transitive_closure(g);
  // catch isn't printing nicely
  if (g_scc_closure != g_closure)
    {
      std::cerr << "original:\n"
		<< g << "SCC finder:\n"
		<< g_scc_closure << "SCCs independently:\n"
		<< g_closure;
    }
  CHECK(g_scc_closure == g_closure);
}

TEST_CASE("randomly-generated graphs")
{
  std::mt19937 gen;
  auto seed = gen();
  // NOTES:
  //   Graphs of size 6 are plenty big enough to shake out bugs.
  //   There are O(2^k^2) possible directed graphs of size k.
  //   Testing costs are O(k^3) so we restrict accordingly.
  uint64_t budget = 10000;
  for (size_t k = 0; k < 7; ++k)
    {
      uint64_t count = std::min(static_cast<uint64_t>(1) << (k * k),
				budget / (k ? k * k * k : 1));
      INFO("testing with " << count << " graphs of size " << k);
      for (uint64_t n = 0; n < count; ++n, ++seed)
	{
	  gen.seed(seed);
	  Graph g = invent(k, gen);
	  std::ostringstream os;
	  os << "a graph of " << k << " nodes generated using seed " << seed;
	  GIVEN(os.str()) { process(g); }
	}
    }
}

} // namespace Test
