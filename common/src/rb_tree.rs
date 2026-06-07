//! Ordered map as a red-black tree backed by a generational arena.
//!
//! [`RedBlackTree`] provides `no_std` insert, lookup, removal, and in-order traversal
//! with `O(log n)` worst-case height guarantees. Nodes live in a [`generational_arena::Arena`],
//! so [`ArenaIndex`] handles stay stable across unrelated inserts until the node is removed.
//!
use core::cmp::Ordering;

use generational_arena::{Arena, Index as ArenaIndex};

/// Ordered map implemented as a red-black binary search tree in a generational arena.
///
/// Stable [`ArenaIndex`] values survive unrelated insertions until the node is removed.
pub struct RedBlackTree<K, V> {
    arena: Arena<Node<K, V>>,
    root: Option<ArenaIndex>,
    len: usize,
}

impl<K: Ord, V> RedBlackTree<K, V> {
    /// Creates an empty tree.
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
            root: None,
            len: 0,
        }
    }

    /// Returns the number of key-value pairs in the tree.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the tree contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if `key` is present in the tree.
    pub fn contains(&self, key: &K) -> bool {
        self.find_node(key).is_some()
    }

    /// Returns an immutable reference to the value for `key`, if present.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.find_node(key).map(|idx| &self.arena[idx].value)
    }

    /// Returns a mutable reference to the value for `key`, if present.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.find_node(key).map(|idx| &mut self.arena[idx].value)
    }

    /// Returns the arena index of the node with `key`, if present.
    pub fn find_node(&self, key: &K) -> Option<ArenaIndex> {
        let mut current = self.root;
        while let Some(idx) = current {
            match key.cmp(&self.arena[idx].key) {
                Ordering::Equal => return Some(idx),
                Ordering::Less => current = self.arena[idx].left,
                Ordering::Greater => current = self.arena[idx].right,
            }
        }
        None
    }

    /// Returns a reference to the smallest key in the tree.
    pub fn min(&self) -> Option<&K> {
        self.subtree_min(self.root).map(|idx| &self.arena[idx].key)
    }

    /// Returns a reference to the largest key in the tree.
    pub fn max(&self) -> Option<&K> {
        self.subtree_max(self.root).map(|idx| &self.arena[idx].key)
    }

    /// Inserts or updates `key` with `value`.
    ///
    /// Returns the arena index of the node. If the key already existed, the value
    /// is overwritten and the existing index is returned.
    pub fn insert(&mut self, key: K, value: V) -> ArenaIndex {
        let mut parent = None;
        let mut current = self.root;

        while let Some(cur_idx) = current {
            match key.cmp(&self.arena[cur_idx].key) {
                Ordering::Equal => {
                    self.arena[cur_idx].value = value;
                    return cur_idx;
                }
                Ordering::Less => {
                    parent = Some(cur_idx);
                    current = self.arena[cur_idx].left;
                }
                Ordering::Greater => {
                    parent = Some(cur_idx);
                    current = self.arena[cur_idx].right;
                }
            }
        }

        let new_idx = self.arena.insert(Node {
            key,
            value,
            color: Color::Red,
            parent: None,
            left: None,
            right: None,
        });
        self.len += 1;
        self.arena[new_idx].parent = parent;

        match parent {
            None => self.root = Some(new_idx),
            Some(p) => {
                let branch = if self.arena[new_idx].key < self.arena[p].key {
                    Branch::Left
                } else {
                    Branch::Right
                };
                self.set_child(p, branch, Some(new_idx));
            }
        }

        self.insert_fixup(new_idx);
        new_idx
    }

    /// Removes the entry for `key` and returns its value, if the key was present.
    ///
    /// Any external [`ArenaIndex`] for that node must not be used after this call.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.find_node(key)?;
        self.detach_node(idx);
        Some(
            self.arena
                .remove(idx)
                .expect("detached node must exist")
                .value,
        )
    }

    /// Returns a shared reference to a node by arena index, if still valid.
    pub fn arena_get(&self, idx: ArenaIndex) -> Option<&Node<K, V>> {
        self.arena.get(idx)
    }

    /// Walks the tree in ascending key order.
    ///
    /// The callback receives each key and node color.
    pub fn for_each_in_order<F>(&self, mut f: F)
    where
        F: FnMut(&K, Color),
    {
        self.walk_in_order(self.root, &mut f);
    }

    /// Returns the child index at `branch` (`Left` or `Right`) of the node at `idx`.
    fn link(&self, idx: ArenaIndex, branch: Branch) -> Option<ArenaIndex> {
        let node = &self.arena[idx];
        match branch {
            Branch::Left => node.left,
            Branch::Right => node.right,
        }
    }

    /// Sets the left or right child pointer of `parent` to `child`.
    ///
    /// Does not update `child.parent`; callers must keep parent links consistent.
    fn set_child(&mut self, parent: ArenaIndex, branch: Branch, child: Option<ArenaIndex>) {
        let node = &mut self.arena[parent];
        match branch {
            Branch::Left => node.left = child,
            Branch::Right => node.right = child,
        }
    }

    /// Returns which side of `parent` holds `child` as a direct child.
    ///
    /// Callers must ensure `child` is the left or right child of `parent`.
    fn branch_of_child(&self, parent: ArenaIndex, child: ArenaIndex) -> Branch {
        if self.arena[parent].left == Some(child) {
            Branch::Left
        } else {
            Branch::Right
        }
    }

    /// Returns the index of the minimum-key node in the subtree rooted at `node`.
    ///
    /// If `node` is `None`, returns `None`.
    fn subtree_min(&self, mut node: Option<ArenaIndex>) -> Option<ArenaIndex> {
        let mut result = node;
        while let Some(idx) = node {
            result = Some(idx);
            node = self.arena[idx].left;
        }
        result
    }

    /// Returns the index of the maximum-key node in the subtree rooted at `node`.
    ///
    /// If `node` is `None`, returns `None`.
    fn subtree_max(&self, mut node: Option<ArenaIndex>) -> Option<ArenaIndex> {
        let mut result = node;
        while let Some(idx) = node {
            result = Some(idx);
            node = self.arena[idx].right;
        }
        result
    }

    /// Returns the color of `node`, or [`Color::Black`] if `node` is `None` (NIL leaf).
    fn color_of(&self, node: Option<ArenaIndex>) -> Color {
        node.map_or(Color::Black, |idx| self.arena[idx].color)
    }

    /// Returns the colors of the sibling's near and far nephews relative to the extra-black node.
    ///
    /// `branch` is the side of the parent on which the extra-black node sits; the near nephew
    /// is on the same side as that node, the far nephew on the opposite side. Missing sibling or
    /// nephews are treated as black.
    fn nephew_colors(&self, sibling: Option<ArenaIndex>, branch: Branch) -> (Color, Color) {
        let Some(s_idx) = sibling else {
            return (Color::Black, Color::Black);
        };
        let near = self.link(s_idx, branch);
        let far = self.link(s_idx, branch.opposite());
        (self.color_of(near), self.color_of(far))
    }

    /// Recursively visits the subtree at `current` in ascending key order.
    fn walk_in_order<F>(&self, current: Option<ArenaIndex>, f: &mut F)
    where
        F: FnMut(&K, Color),
    {
        if let Some(idx) = current {
            let left = self.arena[idx].left;
            let right = self.arena[idx].right;
            let key = &self.arena[idx].key;
            let color = self.arena[idx].color;
            self.walk_in_order(left, f);
            f(key, color);
            self.walk_in_order(right, f);
        }
    }

    // ── Deletion ─────────────────────────────────────────────────────────────

    /// Detaches a node from the tree and runs delete fixup. Does not remove from the arena.
    fn detach_node(&mut self, z: ArenaIndex) {
        self.len -= 1;

        let z_left = self.arena[z].left;
        let z_right = self.arena[z].right;

        let (fixup_node, deleted_was_black) = if z_left.is_none() {
            let color = self.arena[z].color;
            self.transplant(z, z_right);
            (z_right, color)
        } else if z_right.is_none() {
            let color = self.arena[z].color;
            self.transplant(z, z_left);
            (z_left, color)
        } else {
            self.detach_two_children(z)
        };

        if deleted_was_black == Color::Black {
            self.delete_fixup(fixup_node);
        }
    }

    /// Deletes a node that has both children by swapping in the successor.
    fn detach_two_children(&mut self, z: ArenaIndex) -> (Option<ArenaIndex>, Color) {
        let z_right = self.arena[z].right.unwrap();
        let successor = self.subtree_min(Some(z_right)).unwrap();
        let successor_color = self.arena[successor].color;
        let successor_right = self.arena[successor].right;

        if self.arena[successor].parent == Some(z) {
            if let Some(sr) = successor_right {
                self.arena[sr].parent = Some(successor);
            }
        } else {
            self.transplant(successor, successor_right);
            self.arena[successor].right = Some(z_right);
            self.arena[z_right].parent = Some(successor);
        }

        self.transplant(z, Some(successor));
        self.arena[successor].left = self.arena[z].left;
        if let Some(zl) = self.arena[successor].left {
            self.arena[zl].parent = Some(successor);
        }
        self.arena[successor].color = self.arena[z].color;

        (successor_right, successor_color)
    }

    /// Replaces the subtree rooted at `u` with the subtree rooted at `v` (possibly `None`).
    fn transplant(&mut self, u: ArenaIndex, v: Option<ArenaIndex>) {
        let u_parent = self.arena[u].parent;
        match u_parent {
            None => self.root = v,
            Some(p) => {
                let branch = self.branch_of_child(p, u);
                self.set_child(p, branch, v);
            }
        }
        if let Some(v_idx) = v {
            self.arena[v_idx].parent = u_parent;
        }
    }

    // CLRS "left rotate" / "right rotate" preserve the BST order of keys and only
    // rewire parent/child pointers. Fixup passes `branch` so the left- and right-handed
    // cases share one implementation.

    /// Rotates through pivot `x` in the direction of `branch` (the "inner" rotation).
    ///
    /// - [`Branch::Left`] → [`Self::left_rotate`] at `x`: the pivot's **right** child moves up.
    /// - [`Branch::Right`] → [`Self::right_rotate`] at `x`: the pivot's **left** child moves up.
    ///
    /// In insert fixup this straightens a red-red "triangle" (case 2). In delete fixup it
    /// is used when the sibling is red (case 1) and in the final balancing step (case 4).
    fn rotate_in(&mut self, x: ArenaIndex, branch: Branch) {
        match branch {
            Branch::Left => self.left_rotate(x),
            Branch::Right => self.right_rotate(x),
        }
    }

    /// Rotates through pivot `x` away from `branch` (the "outer" rotation).
    ///
    /// This is the inverse pairing of [`Self::rotate_in`]:
    /// `rotate_out(_, Left)` calls [`Self::right_rotate`], and
    /// `rotate_out(_, Right)` calls [`Self::left_rotate`].
    ///
    /// In insert fixup this finishes case 3 after the tree is a red-red "line".
    fn rotate_out(&mut self, x: ArenaIndex, branch: Branch) {
        match branch {
            Branch::Left => self.right_rotate(x),
            Branch::Right => self.left_rotate(x),
        }
    }

    /// Standard left rotation at `x`. Requires a right child `y`.
    ///
    /// `x` must not be `None` in pointer terms; here it is always a valid index.
    /// After rotation, `y` occupies the position `x` had relative to `x`'s parent.
    ///
    /// ```text
    ///      xp                      xp
    ///      /                       /
    ///     x                       y
    ///    / \        left          / \
    ///   α  y        rotate       x   γ
    ///     / \        ===>       / \
    ///    β  γ                   α  β
    /// ```
    ///
    /// Steps: hang `y`'s left subtree on `x`'s right, lift `y` to `x`'s parent link,
    /// then make `x` the left child of `y`.
    fn left_rotate(&mut self, x: ArenaIndex) {
        let y = self.arena[x]
            .right
            .expect("left_rotate requires a right child");

        self.arena[x].right = self.arena[y].left;
        if let Some(yl) = self.arena[y].left {
            self.arena[yl].parent = Some(x);
        }

        let xp = self.arena[x].parent;
        self.arena[y].parent = xp;

        match xp {
            None => self.root = Some(y),
            Some(p) => {
                let branch = self.branch_of_child(p, x);
                self.set_child(p, branch, Some(y));
            }
        }

        self.arena[y].left = Some(x);
        self.arena[x].parent = Some(y);
    }

    /// Standard right rotation at `x` — mirror image of [`Self::left_rotate`].
    ///
    /// Requires a left child `y`. Used symmetrically whenever the fixup side is
    /// [`Branch::Right`].
    ///
    /// ```text
    ///        xp                      xp
    ///        /                       /
    ///       x                       y
    ///      / \      right           / \
    ///     y  γ      rotate         α  x
    ///    / \         ===>              / \
    ///   α  β                           β  γ
    /// ```
    fn right_rotate(&mut self, x: ArenaIndex) {
        let y = self.arena[x]
            .left
            .expect("right_rotate requires a left child");

        self.arena[x].left = self.arena[y].right;
        if let Some(yr) = self.arena[y].right {
            self.arena[yr].parent = Some(x);
        }

        let xp = self.arena[x].parent;
        self.arena[y].parent = xp;

        match xp {
            None => self.root = Some(y),
            Some(p) => {
                let branch = self.branch_of_child(p, x);
                self.set_child(p, branch, Some(y));
            }
        }

        self.arena[y].right = Some(x);
        self.arena[x].parent = Some(y);
    }

    // A newly inserted node starts red. Only property violated is: no two consecutive
    // red edges. Loop climbs toward the root while the parent is red; the root is
    // forced black at the end (property 2).

    /// Restores red-black invariants after inserting a red node at `z`.
    ///
    /// Walks upward while `z`'s parent is red, dispatching [`Self::insert_fixup_iteration`]
    /// for the side of the grandparent (`branch`). Terminates when the parent is black or
    /// the loop recolors up to the root. Finally paints the root black.
    fn insert_fixup(&mut self, mut z: ArenaIndex) {
        while let Some(parent) = self.arena[z].parent {
            if self.arena[parent].color != Color::Red {
                break;
            }

            let grandparent = self.arena[parent]
                .parent
                .expect("red parent implies grandparent exists");

            let branch = if self.arena[grandparent].left == Some(parent) {
                Branch::Left
            } else {
                Branch::Right
            };

            z = self.insert_fixup_iteration(z, parent, grandparent, branch);
        }

        if let Some(root) = self.root {
            self.arena[root].color = Color::Black;
        }
    }

    /// One insert-fixup iteration for the configuration where `parent` is
    /// the `branch` child of `grandparent`.
    ///
    /// Returns the index that may still violate the red parent rule (only case 1 continues
    /// the loop with a new `z`).
    ///
    /// **Case 1 — uncle is red:** recolor parent, uncle, and grandparent; move `z` to
    /// grandparent (may need another iteration).
    ///
    /// **Case 2 — uncle black, `z` on the far side (triangle):** [`Self::rotate_in`] on
    /// parent to convert to case 3.
    ///
    /// **Case 3 — uncle black, `z` on the near side (line):** blacken parent, redden
    /// grandparent, [`Self::rotate_out`] on grandparent; loop ends because parent is black.
    fn insert_fixup_iteration(
        &mut self,
        z: ArenaIndex,
        parent: ArenaIndex,
        grandparent: ArenaIndex,
        branch: Branch,
    ) -> ArenaIndex {
        let uncle = self.link(grandparent, branch.opposite());

        if self.color_of(uncle) == Color::Red {
            self.arena[parent].color = Color::Black;
            if let Some(u) = uncle {
                self.arena[u].color = Color::Black;
            }
            self.arena[grandparent].color = Color::Red;
            return grandparent;
        }

        let mut z = z;
        let on_far_side = self.link(parent, branch.opposite()) == Some(z);
        if on_far_side {
            z = parent;
            self.rotate_in(z, branch);
        }

        let parent = self.arena[z].parent.expect("parent exists after rotation");
        let grandparent = self.arena[parent]
            .parent
            .expect("grandparent exists for red parent");

        self.arena[parent].color = Color::Black;
        self.arena[grandparent].color = Color::Red;
        self.rotate_out(grandparent, branch);
        z
    }

    // ── Delete fixup ───────────────────────────────────────────────────────────
    //
    // Removing a black node leaves an extra "black deficit" on a node (or NIL = None).
    // `extra_black` is that node: it is treated as doubly black until the loop rebalances.

    /// Restores red-black invariants after a black node was removed.
    ///
    /// `extra_black` is the node that inherited the deleted node's position (or `None` for
    /// NIL). The loop runs while that node is not the root and is still considered black
    /// (including NIL via [`Self::color_of`]). Each step calls
    /// [`Self::delete_fixup_iteration`]. When the loop exits, the node is painted black.
    fn delete_fixup(&mut self, mut extra_black: Option<ArenaIndex>) {
        while extra_black != self.root && self.color_of(extra_black) == Color::Black {
            let Some(x) = extra_black else {
                break;
            };

            let Some(parent) = self.arena[x].parent else {
                break;
            };

            let branch = if self.arena[parent].left == extra_black {
                Branch::Left
            } else {
                Branch::Right
            };

            extra_black = self.delete_fixup_iteration(extra_black, parent, branch);
        }

        if let Some(idx) = extra_black {
            self.arena[idx].color = Color::Black;
        }
    }

    /// One delete-fixup iteration when the extra-black node is on `branch`
    /// side of `parent` (`None` means NIL on that side).
    ///
    /// `sibling` is the other child of `parent`. Nephews are interpreted via
    /// [`Self::nephew_colors`] relative to the extra-black side.
    ///
    /// **Case 1 — sibling red:** recolor sibling black, parent red, [`Self::rotate_in`]
    /// on parent to pull down a black sibling; fall through to case 2/3/4.
    ///
    /// **Case 2 — sibling black, both nephews black:** redden sibling, move extra-black
    /// to parent (may continue loop).
    ///
    /// **Case 3 — sibling black, far nephew black:** blacken near nephew, redden sibling,
    /// [`Self::rotate_out`] on sibling to manufacture a red far nephew.
    ///
    /// **Case 4 — sibling black, far nephew red:** copy colors from parent, blacken far
    /// nephew and parent, [`Self::rotate_in`] on parent; returns [`Self::root`] to end loop.
    fn delete_fixup_iteration(
        &mut self,
        _extra_black: Option<ArenaIndex>,
        parent: ArenaIndex,
        branch: Branch,
    ) -> Option<ArenaIndex> {
        let mut sibling = self.link(parent, branch.opposite());

        let sibling_side = branch.opposite();

        if self.color_of(sibling) == Color::Red {
            if let Some(w) = sibling {
                self.arena[w].color = Color::Black;
            }
            self.arena[parent].color = Color::Red;
            self.rotate_in(parent, branch);
            sibling = self.link(parent, branch.opposite());
        }

        let (near_color, far_color) = self.nephew_colors(sibling, sibling_side);

        if near_color == Color::Black && far_color == Color::Black {
            if let Some(w) = sibling {
                self.arena[w].color = Color::Red;
            }
            return Some(parent);
        }

        if far_color == Color::Black {
            if let Some(w) = sibling {
                if let Some(near) = self.link(w, sibling_side) {
                    self.arena[near].color = Color::Black;
                }
                self.arena[w].color = Color::Red;
                self.rotate_out(w, sibling_side);
            }
            sibling = self.link(parent, branch.opposite());
        }

        if let Some(w) = sibling {
            self.arena[w].color = self.arena[parent].color;
        }
        self.arena[parent].color = Color::Black;
        if let Some(w) = sibling {
            if let Some(far) = self.link(w, sibling_side.opposite()) {
                self.arena[far].color = Color::Black;
            }
        }
        self.rotate_in(parent, branch);
        self.root
    }
}

impl<K: Ord, V> Default for RedBlackTree<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// A single tree node. Internal links are crate-private; keys and values are public
/// for callers that store handles (e.g. cancel-by-index).
pub struct Node<K, V> {
    /// Sort key.
    pub key: K,
    /// Associated value.
    pub value: V,
    pub(crate) color: Color,
    pub(crate) parent: Option<ArenaIndex>,
    pub(crate) left: Option<ArenaIndex>,
    pub(crate) right: Option<ArenaIndex>,
}

/// Node color in the red-black tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    /// Red node (may not be adjacent to another red node).
    Red,
    /// Black node (root is always black).
    Black,
}

/// Which child slot of a parent (`left` or `right`).
///
/// Fixup code is written once for the [`Branch::Left`] configuration; the [`Branch::Right`]
/// case reuses the same logic with `branch` and `branch.opposite()` swapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Branch {
    Left,
    Right,
}

impl Branch {
    /// Returns the other child direction.
    const fn opposite(self) -> Self {
        match self {
            Branch::Left => Branch::Right,
            Branch::Right => Branch::Left,
        }
    }
}
