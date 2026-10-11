#include "revkit/inputs/param_id.h"

#include "revkit/facts/codec.h"

#include <algorithm>
#include <deque>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace revkit::inputs {

namespace an = revkit::analysis;

std::optional<ParamIdMode> parse_param_id_mode(const std::string &s) {
  if (s == "auto") return ParamIdMode::automatic;
  if (s == "on") return ParamIdMode::on;
  if (s == "off") return ParamIdMode::off;
  return std::nullopt;
}

const char *param_id_mode_name(ParamIdMode m) {
  switch (m) {
    case ParamIdMode::automatic: return "auto";
    case ParamIdMode::on: return "on";
    case ParamIdMode::off: return "off";
  }
  return "?";
}

bool param_id_default(const loader::Image &image, const std::vector<lift::BlockFacts> &memory) {
  // "only do for windows by default, windows has good type info", and
  // only below MEDIUM_SIZE_PROGRAM addresses.
  if (image.format != loader::Format::pe) return false;
  std::uint64_t addresses = 0;
  if (!memory.empty()) {
    for (const lift::BlockFacts &b : memory) addresses += b.end - b.start + 1;
  } else {
    for (const loader::Block &b : image.blocks) addresses += b.size;
  }
  return addresses < (std::uint64_t{2} << 20);
}

bool param_id_enabled(ParamIdMode mode, const loader::Image &image, const std::vector<lift::BlockFacts> &memory) {
  switch (mode) {
    case ParamIdMode::on: return true;
    case ParamIdMode::off: return false;
    case ParamIdMode::automatic: return param_id_default(image, memory);
  }
  return false;
}

std::vector<CallGraphNode> call_graph_nodes(const an::FunctionList &functions, const an::ProgramInfo &info,
                                            const std::function<const an::FlowGraph &(std::uint64_t key)> &flow) {
  std::unordered_map<std::uint64_t, std::uint16_t> seeds;
  for (const an::Seed &s : info.seeds) seeds[s.address] |= s.flags;
  std::unordered_map<std::uint64_t, const an::FunctionInfo *> by_entry;
  for (const an::FunctionInfo &f : functions.functions) by_entry.emplace(f.entry.offset, &f);
  // getThunkedFunction(true): through chains of thunks to the last one's
  // target; an import (or a target that isn't a function) is external.
  auto final_target = [&](const an::FunctionInfo &f) -> std::optional<std::uint64_t> {
    const an::FunctionInfo *at = &f;
    std::unordered_set<std::uint64_t> seen;
    while (at->flags & an::kFunctionThunk) {
      if (!at->import.empty() || !seen.insert(at->entry.offset).second) return std::nullopt;
      auto it = by_entry.find(at->thunk_target);
      if (it == by_entry.end()) return std::nullopt;
      at = it->second;
    }
    return at->entry.offset;
  };
  std::vector<CallGraphNode> out;
  out.reserve(functions.functions.size());
  for (const an::FunctionInfo &f : functions.functions) {
    CallGraphNode n;
    n.entry = f.entry.offset;
    if (auto it = seeds.find(n.entry); it != seeds.end())
      n.entry_point = (it->second & (an::kSeedEntry | an::kSeedExport | an::kSeedProcessor)) != 0;
    if (f.flags & an::kFunctionThunk) {
      n.thunk = true;
      n.thunk_target = final_target(f);
      if (!n.thunk_target && !f.import.empty()) {
        // Ghidra numbers external locations as the loader creates them,
        // in import order: approximated by the slot's position.
        auto it = std::lower_bound(info.imports.begin(), info.imports.end(), f.thunk_target,
                                   [](const an::ImportSlot &s, std::uint64_t a) { return s.address < a; });
        n.external = 1 + static_cast<std::uint64_t>(it - info.imports.begin());
      }
      out.push_back(std::move(n));
      continue;
    }
    const an::FlowGraph &g = flow(f.flow_key());
    for (const an::FlowInsn &i : g.insns) {
      if (!f.body.contains(facts::Address{f.entry.space, i.address})) continue;
      // Calls, and jumps that are calls to Ghidra: an unconditional jump to
      // another function's entry from outside one gets a CALL_RETURN
      // override (SharedReturnAnalysisCmd, as inputs::assemble_function
      // gives it), making its reference a call (CALL_TERMINATOR).
      const bool shared_return = i.kind == an::FlowKind::jump && i.targets.size() == 1 &&
                                 by_entry.contains(i.targets[0]) && i.targets[0] != f.entry.offset &&
                                 !by_entry.contains(i.address);
      const bool call = i.kind == an::FlowKind::call || i.kind == an::FlowKind::call_indirect || shared_return ||
                        (i.tail_call && (i.kind == an::FlowKind::jump || i.kind == an::FlowKind::jump_indirect));
      if (!call) continue;
      std::vector<std::uint64_t> targets = i.targets;
      std::sort(targets.begin(), targets.end());
      targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
      for (std::uint64_t t : targets)  // a Thumb target's low bit tags it
        n.calls.push_back(!by_entry.contains(t) && by_entry.contains(t & ~std::uint64_t{1}) ? t & ~std::uint64_t{1} : t);
    }
    out.push_back(std::move(n));
  }
  return out;
}

namespace {

// An Address as a HashSet<Address> key: GenericAddress.hashCode is the
// space's hash shifted left 16, xor the offset's halves.
struct JavaAddress {
  int space = 0;  // 0: the code space, 1: EXTERNAL
  std::uint64_t offset = 0;
  friend bool operator==(const JavaAddress &, const JavaAddress &) = default;
  friend auto operator<=>(const JavaAddress &, const JavaAddress &) = default;
};

// java.lang.String.hashCode.
std::int32_t java_string_hash(const std::string &s) {
  std::uint32_t h = 0;
  for (unsigned char c : s) h = 31 * h + c;
  return static_cast<std::int32_t>(h);
}

// java.util.HashMap (JDK 8 and later) far enough to know the order a
// HashSet iterates its keys in: buckets by spread hash, each a list in
// insertion order, which becomes a red-black tree (TreeNode) past 8 keys
// in a table of 64 or more, linking a new key after its parent in the
// tree and moving the root to the front of the bucket; resizing splits
// buckets (untreeifying small halves) keeping their order.
class JavaHashSet {
 public:
  // Returns false if the key was there.
  bool add(std::int32_t key_hash, JavaAddress key) {
    const std::int32_t h = key_hash ^ static_cast<std::int32_t>(static_cast<std::uint32_t>(key_hash) >> 16);
    if (tab_.empty()) resize();
    const std::size_t n = tab_.size();
    const std::size_t i = static_cast<std::uint32_t>(h) & (n - 1);
    int p = tab_[i];
    if (p < 0) {
      const int x = make(h, key, -1);
      tab_[i] = x;
    } else if (nodes_[p].hash == h && nodes_[p].key == key) {
      return false;
    } else if (nodes_[p].tree) {
      if (!put_tree(p, h, key)) return false;
    } else {
      for (int bin = 0;; ++bin) {
        const int e = nodes_[p].next;
        if (e < 0) {
          const int x = make(h, key, -1);
          nodes_[p].next = x;
          if (bin >= kTreeify - 1) treeify_bin(h);
          break;
        }
        if (nodes_[e].hash == h && nodes_[e].key == key) return false;
        p = e;
      }
    }
    if (++size_ > threshold_) resize();
    return true;
  }

  std::vector<JavaAddress> order() const {
    std::vector<JavaAddress> out;
    for (int head : tab_)
      for (int e = head; e >= 0; e = nodes_[e].next) out.push_back(nodes_[e].key);
    return out;
  }

 private:
  static constexpr int kTreeify = 8, kUntreeify = 6, kMinTreeifyCapacity = 64;
  struct Node {
    std::int32_t hash;
    JavaAddress key;
    int next = -1;
    // TreeNode
    bool tree = false, red = false;
    int parent = -1, left = -1, right = -1, prev = -1;
  };

  int make(std::int32_t h, JavaAddress key, int next) {
    nodes_.push_back(Node{h, key, next});
    return static_cast<int>(nodes_.size() - 1);
  }
  Node &n(int i) { return nodes_[static_cast<std::size_t>(i)]; }

  // Keys of equal hash: Java compares them only by identity hash codes
  // (Address isn't Comparable to its own class), which revkit can't know;
  // address order stands in.
  int compare(int p, std::int32_t h, const JavaAddress &k) {
    if (n(p).hash > h) return -1;
    if (n(p).hash < h) return 1;
    return k < n(p).key ? -1 : 1;
  }

  void resize() {
    const std::size_t old_cap = tab_.size();
    std::size_t cap;
    if (old_cap == 0) {
      cap = 16;
      threshold_ = 12;
    } else {
      cap = old_cap * 2;
      threshold_ *= 2;
    }
    std::vector<int> tab(cap, -1);
    for (std::size_t j = 0; j < old_cap; ++j) {
      const int e = tab_[j];
      if (e < 0) continue;
      if (n(e).next < 0) {
        tab[static_cast<std::uint32_t>(n(e).hash) & (cap - 1)] = e;
      } else if (n(e).tree) {
        split(tab, e, j, old_cap);
      } else {
        int lo_head = -1, lo_tail = -1, hi_head = -1, hi_tail = -1;
        for (int x = e, next; x >= 0; x = next) {
          next = n(x).next;
          if ((static_cast<std::uint32_t>(n(x).hash) & old_cap) == 0) {
            if (lo_tail < 0) lo_head = x;
            else n(lo_tail).next = x;
            lo_tail = x;
          } else {
            if (hi_tail < 0) hi_head = x;
            else n(hi_tail).next = x;
            hi_tail = x;
          }
        }
        if (lo_tail >= 0) {
          n(lo_tail).next = -1;
          tab[j] = lo_head;
        }
        if (hi_tail >= 0) {
          n(hi_tail).next = -1;
          tab[j + old_cap] = hi_head;
        }
      }
    }
    tab_ = std::move(tab);
  }

  void treeify_bin(std::int32_t h) {
    const std::size_t cap = tab_.size();
    if (cap < kMinTreeifyCapacity) {
      resize();
      return;
    }
    const std::size_t index = static_cast<std::uint32_t>(h) & (cap - 1);
    int tl = -1;
    for (int e = tab_[index]; e >= 0; e = n(e).next) {
      n(e).tree = true;
      n(e).prev = tl;
      tl = e;
    }
    if (tab_[index] >= 0) treeify(tab_, tab_[index]);
  }

  void untreeify(int head) {
    for (int e = head; e >= 0; e = n(e).next) {
      n(e).tree = false;
      n(e).parent = n(e).left = n(e).right = n(e).prev = -1;
      n(e).red = false;
    }
  }

  void treeify(std::vector<int> &tab, int head) {
    int root = -1;
    for (int x = head, next; x >= 0; x = next) {
      next = n(x).next;
      n(x).left = n(x).right = -1;
      if (root < 0) {
        n(x).parent = -1;
        n(x).red = false;
        root = x;
        continue;
      }
      for (int p = root;;) {
        const int dir = compare(p, n(x).hash, n(x).key);
        const int xp = p;
        p = dir <= 0 ? n(p).left : n(p).right;
        if (p < 0) {
          n(x).parent = xp;
          if (dir <= 0) n(xp).left = x;
          else n(xp).right = x;
          root = balance_insertion(root, x);
          break;
        }
      }
    }
    move_root_to_front(tab, root);
  }

  int root_of(int p) {
    while (n(p).parent >= 0) p = n(p).parent;
    return p;
  }

  bool put_tree(int first, std::int32_t h, const JavaAddress &k) {
    const int root = n(first).parent >= 0 ? root_of(first) : first;
    for (int p = root;;) {
      if (n(p).hash == h && n(p).key == k) return false;
      if (n(p).hash == h) {
        // Java searches both subtrees for the key before breaking the tie.
        std::vector<int> stack{p};
        while (!stack.empty()) {
          const int q = stack.back();
          stack.pop_back();
          if (q < 0) continue;
          if (n(q).hash == h && n(q).key == k) return false;
          stack.push_back(n(q).left);
          stack.push_back(n(q).right);
        }
      }
      const int dir = compare(p, h, k);
      const int xp = p;
      p = dir <= 0 ? n(p).left : n(p).right;
      if (p < 0) {
        const int xpn = n(xp).next;
        const int x = make(h, k, xpn);  // (nodes_ may move: no references held)
        n(x).tree = true;
        if (dir <= 0) n(xp).left = x;
        else n(xp).right = x;
        n(xp).next = x;
        n(x).parent = n(x).prev = xp;
        if (xpn >= 0) n(xpn).prev = x;
        move_root_to_front(tab_, balance_insertion(root, x));
        return true;
      }
    }
  }

  void split(std::vector<int> &tab, int b, std::size_t index, std::size_t bit) {
    int lo_head = -1, lo_tail = -1, hi_head = -1, hi_tail = -1;
    int lc = 0, hc = 0;
    for (int e = b, next; e >= 0; e = next) {
      next = n(e).next;
      n(e).next = -1;
      if ((static_cast<std::uint32_t>(n(e).hash) & bit) == 0) {
        n(e).prev = lo_tail;
        if (lo_tail < 0) lo_head = e;
        else n(lo_tail).next = e;
        lo_tail = e;
        ++lc;
      } else {
        n(e).prev = hi_tail;
        if (hi_tail < 0) hi_head = e;
        else n(hi_tail).next = e;
        hi_tail = e;
        ++hc;
      }
    }
    if (lo_head >= 0) {
      tab[index] = lo_head;
      if (lc <= kUntreeify) untreeify(lo_head);
      else if (hi_head >= 0) treeify(tab, lo_head);
    }
    if (hi_head >= 0) {
      tab[index + bit] = hi_head;
      if (hc <= kUntreeify) untreeify(hi_head);
      else if (lo_head >= 0) treeify(tab, hi_head);
    }
  }

  void move_root_to_front(std::vector<int> &tab, int root) {
    if (root < 0) return;
    const std::size_t index = static_cast<std::uint32_t>(n(root).hash) & (tab.size() - 1);
    const int first = tab[index];
    if (root == first) return;
    const int rn = n(root).next, rp = n(root).prev;
    tab[index] = root;
    if (rn >= 0) n(rn).prev = rp;
    if (rp >= 0) n(rp).next = rn;
    if (first >= 0) n(first).prev = root;
    n(root).next = first;
    n(root).prev = -1;
  }

  int rotate_left(int root, int p) {
    int r;
    if (p >= 0 && (r = n(p).right) >= 0) {
      const int rl = n(p).right = n(r).left;
      if (rl >= 0) n(rl).parent = p;
      const int pp = n(r).parent = n(p).parent;
      if (pp < 0) {
        root = r;
        n(r).red = false;
      } else if (n(pp).left == p) {
        n(pp).left = r;
      } else {
        n(pp).right = r;
      }
      n(r).left = p;
      n(p).parent = r;
    }
    return root;
  }

  int rotate_right(int root, int p) {
    int l;
    if (p >= 0 && (l = n(p).left) >= 0) {
      const int lr = n(p).left = n(l).right;
      if (lr >= 0) n(lr).parent = p;
      const int pp = n(l).parent = n(p).parent;
      if (pp < 0) {
        root = l;
        n(l).red = false;
      } else if (n(pp).right == p) {
        n(pp).right = l;
      } else {
        n(pp).left = l;
      }
      n(l).right = p;
      n(p).parent = l;
    }
    return root;
  }

  int balance_insertion(int root, int x) {
    n(x).red = true;
    for (int xp, xpp, xppl, xppr;;) {
      if ((xp = n(x).parent) < 0) {
        n(x).red = false;
        return x;
      }
      if (!n(xp).red || (xpp = n(xp).parent) < 0) return root;
      if (xp == (xppl = n(xpp).left)) {
        if ((xppr = n(xpp).right) >= 0 && n(xppr).red) {
          n(xppr).red = false;
          n(xp).red = false;
          n(xpp).red = true;
          x = xpp;
        } else {
          if (x == n(xp).right) {
            root = rotate_left(root, x = xp);
            xpp = (xp = n(x).parent) < 0 ? -1 : n(xp).parent;
          }
          if (xp >= 0) {
            n(xp).red = false;
            if (xpp >= 0) {
              n(xpp).red = true;
              root = rotate_right(root, xpp);
            }
          }
        }
      } else {
        if (xppl >= 0 && n(xppl).red) {
          n(xppl).red = false;
          n(xp).red = false;
          n(xpp).red = true;
          x = xpp;
        } else {
          if (x == n(xp).left) {
            root = rotate_right(root, x = xp);
            xpp = (xp = n(x).parent) < 0 ? -1 : n(xp).parent;
          }
          if (xp >= 0) {
            n(xp).red = false;
            if (xpp >= 0) {
              n(xpp).red = true;
              root = rotate_left(root, xpp);
            }
          }
        }
      }
    }
  }

  std::vector<Node> nodes_;
  std::vector<int> tab_;
  std::size_t size_ = 0, threshold_ = 0;
};

// The order a HashSet<Address> holding `keys` (inserted in that order)
// iterates them in.
std::vector<JavaAddress> java_hash_order(const std::vector<JavaAddress> &keys, const std::string &space) {
  // GenericAddressSpace.computeHashCode: name.hashCode() ^ type (TYPE_RAM 1,
  // TYPE_EXTERNAL 10).
  const std::int32_t hashes[2] = {java_string_hash(space) ^ 1, java_string_hash("EXTERNAL") ^ 10};
  JavaHashSet set;
  for (const JavaAddress &k : keys) {
    const std::int32_t h3 = static_cast<std::int32_t>(k.offset >> 32) ^ static_cast<std::int32_t>(k.offset);
    set.add(static_cast<std::int32_t>(static_cast<std::uint32_t>(hashes[k.space]) << 16) ^ h3, k);
  }
  return set.order();
}

}  // namespace

std::vector<std::uint64_t> java_address_set_order(const std::vector<std::uint64_t> &keys, const std::string &space) {
  std::vector<JavaAddress> in;
  for (std::uint64_t k : keys) in.push_back({0, k});
  std::vector<std::uint64_t> out;
  for (const JavaAddress &a : java_hash_order(in, space)) out.push_back(a.offset);
  return out;
}

ParamIdPlan param_id_plan(const std::vector<CallGraphNode> &nodes, const std::string &space) {
  ParamIdPlan plan;
  std::unordered_map<std::uint64_t, const CallGraphNode *> by_entry;
  for (const CallGraphNode &n : nodes) by_entry.emplace(n.entry, &n);
  for (const CallGraphNode &n : nodes)
    if (n.thunk) plan.thunks.emplace(n.entry, n.thunk_target);
  // A call to a thunk is a call to what it thunks (killThunks).
  auto resolve = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
    auto it = by_entry.find(a);
    if (it == by_entry.end()) return a;
    if (!it->second->thunk) return a;
    return it->second->thunk_target;
  };

  // findFunctions: the set, filled in address order with each thunk
  // replaced by what it thunks (external functions too, which have no
  // body: they only shape the HashSet the walk's starts come from).
  std::vector<std::uint64_t> inserted;
  std::vector<JavaAddress> keys;
  std::unordered_set<std::uint64_t> in_set;
  for (const CallGraphNode &n : nodes) {
    if (n.thunk && !n.thunk_target) {
      if (n.external) keys.push_back({1, *n.external});
      continue;
    }
    const std::uint64_t e = n.thunk ? *n.thunk_target : n.entry;
    if (!by_entry.contains(e)) continue;
    keys.push_back({0, e});
    if (in_set.insert(e).second) inserted.push_back(e);
  }

  // initializeNode: children are the calls into the set, in order.
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> children;
  std::unordered_set<std::uint64_t> called;
  for (std::uint64_t e : inserted) {
    std::vector<std::uint64_t> &c = children[e];
    for (std::uint64_t to : by_entry.at(e)->calls) {
      called.insert(to);
      std::optional<std::uint64_t> r = resolve(to);
      if (r && in_set.contains(*r)) c.push_back(*r);
    }
  }
  // A call to a thunk is a call reference to the thunk, not its target:
  // the target's own start-ness follows its own references.
  auto is_start = [&](std::uint64_t a) {
    const CallGraphNode *n = by_entry.at(a);
    if (n->entry_point) return true;
    return !called.contains(a);
  };

  std::deque<std::uint64_t> starts;
  for (const JavaAddress &a : java_hash_order(keys, space))
    if (a.space == 0 && is_start(a.offset)) starts.push_back(a.offset);
  std::set<std::uint64_t> unprocessed(inserted.begin(), inserted.end());  // TreeSet: address order
  std::map<std::uint64_t, std::set<std::uint64_t>> deps;
  for (std::uint64_t e : inserted) deps[e];

  struct Frame {
    std::uint64_t address;
    std::size_t next = 0;
  };
  while (!unprocessed.empty()) {
    std::uint64_t start = 0;
    bool found = false;
    while (!starts.empty()) {
      const std::uint64_t a = starts.front();
      starts.pop_front();
      if (unprocessed.contains(a)) {
        start = a;
        found = true;
        break;
      }
    }
    if (!found) start = *unprocessed.begin();
    // processForward.
    std::vector<Frame> stack{{start}};
    std::unordered_set<std::uint64_t> on_stack{start};
    while (!stack.empty()) {
      Frame &cur = stack.back();
      const std::vector<std::uint64_t> &kids = children[cur.address];
      if (cur.next >= kids.size()) {
        unprocessed.erase(cur.address);
        on_stack.erase(cur.address);
        stack.pop_back();
        continue;
      }
      const std::uint64_t child = kids[cur.next++];
      if (on_stack.contains(child)) continue;  // recursion: the call back is dropped
      const std::uint64_t parent = cur.address;
      if (unprocessed.contains(child)) {
        stack.push_back({child});
        on_stack.insert(child);
      }
      deps[parent].insert(child);
    }
  }

  plan.nodes.assign(inserted.begin(), inserted.end());
  std::sort(plan.nodes.begin(), plan.nodes.end());
  for (auto &[node, d] : deps) plan.dependencies[node] = std::vector<std::uint64_t>(d.begin(), d.end());
  return plan;
}

const std::vector<std::uint64_t> &ParamIdPlan::dependencies_of(std::uint64_t node) const {
  static const std::vector<std::uint64_t> none;
  auto it = dependencies.find(node);
  return it != dependencies.end() ? it->second : none;
}

std::vector<std::vector<std::uint64_t>> ParamIdPlan::rounds() const {
  std::unordered_map<std::uint64_t, std::size_t> level;
  std::vector<std::vector<std::uint64_t>> out;
  // Dependencies form a DAG; levels by a memoized walk without recursion.
  for (std::uint64_t root : nodes) {
    if (level.contains(root)) continue;
    std::vector<std::pair<std::uint64_t, std::size_t>> stack{{root, 0}};
    while (!stack.empty()) {
      auto &[n, i] = stack.back();
      const std::vector<std::uint64_t> &d = dependencies_of(n);
      if (i < d.size()) {
        const std::uint64_t c = d[i++];
        if (!level.contains(c)) stack.push_back({c, 0});
        continue;
      }
      std::size_t l = 0;
      for (std::uint64_t c : d) l = std::max(l, level.at(c) + 1);
      level[n] = l;
      stack.pop_back();
    }
  }
  for (std::uint64_t n : nodes) {
    const std::size_t l = level.at(n);
    if (out.size() <= l) out.resize(l + 1);
    out[l].push_back(n);
  }
  return out;
}

void ParamIdPlan::encode(facts::Encoder &e) const {
  facts::encode(e, nodes);
  e.varint(dependencies.size());
  for (const auto &[n, d] : dependencies) {
    e.varint(n);
    facts::encode(e, d);
  }
  e.varint(thunks.size());
  for (const auto &[t, target] : thunks) {
    e.varint(t);
    facts::encode(e, target);
  }
}

ParamIdPlan ParamIdPlan::decode(facts::Decoder &d) {
  ParamIdPlan p;
  p.nodes = facts::decode<std::vector<std::uint64_t>>(d);
  for (std::size_t i = 0, n = d.count(); i < n; ++i) {
    const std::uint64_t node = d.varint();
    p.dependencies[node] = facts::decode<std::vector<std::uint64_t>>(d);
  }
  for (std::size_t i = 0, n = d.count(); i < n; ++i) {
    const std::uint64_t t = d.varint();
    p.thunks[t] = facts::decode<std::optional<std::uint64_t>>(d);
  }
  return p;
}

std::optional<std::string> param_id_skip(const lift::FunctionFacts &f, bool thunk,
                                         const std::vector<lift::BlockFacts> &memory) {
  if (thunk) return std::string("a thunk");
  if (f.signature_source != lift::SignatureSource::default_ && f.signature_source != lift::SignatureSource::analysis)
    return std::string("its signature comes from elsewhere");
  for (const lift::BlockFacts &b : memory)
    if (f.entry >= b.start && f.entry <= b.end) {
      if (b.external || b.name == "EXTERNAL" || b.name == ".plt" || b.name == "__stub_helper")
        return std::string("external glue (") + b.name + ")";
      break;
    }
  return std::nullopt;
}

void apply_param_id(lift::FunctionFacts &f, const lift::CommittedSignature &s) {
  if (s.status != lift::CommittedSignature::Status::committed) return;
  f.signature_source = lift::SignatureSource::analysis;
  f.convention = s.convention;
  f.varargs = s.varargs;
  f.custom_storage = s.custom_storage;
  f.dynamic_storage = false;
  f.params = s.params;
  if (s.return_committed) {
    f.ret = s.ret;
    f.ret.void_storage = false;
  } else {
    // The function's return as it was: Ghidra's DEFAULT "undefined" with
    // no storage (the decompiler is told an unlocked void).
    f.ret = lift::FunctionFacts::Return{};
    f.ret.type = {"typeref", {{"id", std::uint64_t{0xc000000000000000ULL}}, {"name", std::string("undefined")}}, {}};
    f.ret.is_default = true;
    f.ret.storage = std::nullopt;
    f.ret.size = 1;
  }
}

void apply_param_id(lift::DecompilerInputs &inputs, const ParamIdPlan &plan,
                    const std::map<std::uint64_t, lift::CommittedSignature> &results) {
  for (lift::FunctionFacts &f : inputs.functions) {
    std::uint64_t at = f.entry;
    if (auto t = plan.thunks.find(f.entry); t != plan.thunks.end()) {
      if (!t->second || f.signature_source != lift::SignatureSource::default_) continue;
      at = *t->second;
    }
    if (auto it = results.find(at); it != results.end()) apply_param_id(f, it->second);
  }
}

}  // namespace revkit::inputs
