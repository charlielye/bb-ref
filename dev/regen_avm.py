#!/usr/bin/env python3
"""Regenerate src/avm/generated/ from the pin's AVM sources and show what changed. Run after moving the pin.

Reads bb-pilcom's C++ output in barretenberg/cpp/src/barretenberg/vm2/generated/ (the relation
expressions, the lookup/permutation settings, the column layout), the fixed AVM verification key
(vm2/constraining/avm_fixed_vk.hpp) and the AVM constants, and writes two tables that
src/avm/ interprets:

  layout.txt     constants, the column layout (every ColumnAndShifts name in order), the fixed VK
  relations.txt  every relation in bb's flavor order: generated relations as expression trees,
                 lookups and permutations as their column lists

Expressions keep bb's evaluation order exactly: in-circuit every operation is a gate, so the
generated C++ (operator precedence, left associativity, alias hoisting) is the specification. The
one hand-optimized relation bb swaps in (vm2/optimized/relations/poseidon2_perm) is listed by name
and implemented in src/avm/poseidon2_perm.rs.

Usage: dev/regen_avm.py [aztec-packages checkout]   (default: $AZTEC_REPO or pin/aztec-packages)
"""
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REPO = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AZTEC_REPO", HERE / "pin/aztec-packages"))
BB = REPO / "barretenberg/cpp/src/barretenberg"
VM2 = BB / "vm2"
GEN = VM2 / "generated"
OUT = HERE / "src/avm/generated"

HANDWRITTEN = {"optimized_poseidon2_perm"}


def fail(msg):
    sys.exit(f"regen_avm: {msg}")


# ---- column layout ----------------------------------------------------------------------------


def macro_list(text, name):
    m = re.search(rf"#define {name}\(e\) (.*)", text)
    if not m:
        fail(f"no {name} in columns.hpp")
    body = m.group(1)
    if "AVM2_" in body:
        fail(f"{name} is not a flat list")
    return [t.strip()[2:] for t in body.split(",")]


def layout():
    text = (GEN / "columns.hpp").read_text()
    pre = macro_list(text, "AVM2_PRECOMPUTED_ENTITIES_E")
    wires = macro_list(text, "AVM2_WIRE_ENTITIES_E")
    derived = macro_list(text, "AVM2_DERIVED_WITNESS_ENTITIES_E")
    shifted = macro_list(text, "AVM2_SHIFTED_ENTITIES_E")
    to_be_shifted = macro_list(text, "AVM2_TO_BE_SHIFTED_E")
    all_order = re.search(r"#define AVM2_ALL_ENTITIES_E\(e\) (.*)", text).group(1)
    expected = "AVM2_PRECOMPUTED_ENTITIES_E(e), AVM2_WIRE_ENTITIES_E(e), AVM2_DERIVED_WITNESS_ENTITIES_E(e), AVM2_SHIFTED_ENTITIES_E(e)"
    if all_order.strip() != expected:
        fail("unexpected AVM2_ALL_ENTITIES_E order")
    # The verifier batches the to-be-shifted commitments as the last wires (bb WIRES_TO_BE_SHIFTED_*_IDX),
    # so the shifted entities must be exactly those wires, in order.
    if wires[-len(to_be_shifted):] != to_be_shifted:
        fail("to-be-shifted columns are not the trailing wires")
    if shifted != [c + "_shift" for c in to_be_shifted]:
        fail("shifted entities do not mirror the to-be-shifted wires")
    return pre, wires, derived, shifted


def constants():
    out = {}
    az = (BB / "aztec/aztec_constants.hpp").read_text()
    for name in ["AVM_V2_PROOF_LENGTH_IN_FIELDS", "AVM_NUM_PUBLIC_INPUT_COLUMNS"] + [
        f"AVM_PUBLIC_INPUTS_COLUMN_{i}_LENGTH" for i in range(4)
    ]:
        m = re.search(rf"#define {name} (\d+)\b", az)
        if not m:
            fail(f"no {name}")
        out[name] = int(m.group(1))
    m = re.search(r"MAX_AVM_TRACE_LOG_SIZE = (\d+);", (VM2 / "common/constants.hpp").read_text())
    out["MAX_AVM_TRACE_LOG_SIZE"] = int(m.group(1))
    if out["AVM_NUM_PUBLIC_INPUT_COLUMNS"] != 4:
        fail("the verifier reads exactly four public input columns (public_inputs_cols_0_..3_)")
    return out


def fixed_vk(num_precomputed):
    text = (VM2 / "constraining/avm_fixed_vk.hpp").read_text()
    h = re.search(r'vk_hash\(\) \{ return FF\(uint256_t\("(0x[0-9a-f]{64})"\)\); \}', text)
    if not h:
        fail("no fixed vk hash")
    body = text[text.index("get_all()") :]
    body = body[: body.index("};")]
    names = re.findall(r"//\s*(\w+)", body)
    pts = []
    for entry in re.split(r"//\s*\w+", body)[: len(names)]:
        coords = re.findall(r'uint256_t\(\s*"(0x[0-9a-f]{64})"\)', entry)
        if len(coords) == 2:
            pts.append(tuple(coords))
        elif "Commitment::infinity()" in entry and not coords:
            pts.append(None)
        else:
            fail(f"unparsed fixed vk entry: {entry.strip()[:120]}")
    if len(pts) != num_precomputed:
        fail(f"fixed vk has {len(pts)} commitments, expected {num_precomputed}")
    return h.group(1), pts


# ---- relation expressions ---------------------------------------------------------------------

TOKEN = re.compile(r"\s*(?:(\$?[A-Za-z_][A-Za-z_0-9]*)|(#[0-9]+)|(\S))")


def normalize(expr, aliases):
    """Rewrite a generated C++ expression into a token stream of columns, $aliases, #constants, ops."""
    # clang-format breaks lines anywhere, even inside a cast: drop whitespace next to brackets first
    e = re.sub(r"\s+", " ", expr)
    e = re.sub(r"\s*([()<>{}])\s*", r"\1", e)
    e = re.sub(r"static_cast<View>\(in\.get\(C::(\w+)\)\)", r"\1", e)
    e = re.sub(r"in\.get\(C::(\w+)\)", r"\1", e)
    e = re.sub(r"CView\((\w+)\)", r"$\1", e)

    def wide(m):
        limbs = [int(x) for x in re.findall(r"(\d+)UL", m.group(1))]
        if len(limbs) != 4:
            fail(f"bad uint256 constant {m.group(0)}")
        return "#" + str(sum(v << (64 * i) for i, v in enumerate(limbs)))

    e = re.sub(r"FF\(uint256_t\{([^}]*)\}\)", wide, e)
    e = re.sub(r"FF\((\d+)(?:UL|ULL)?\)", r"#\1", e)
    if re.search(r"static_cast|View|FF\(|::|\{", e):
        fail(f"unparsed construct in: {expr.strip()[:200]}")
    # bare alias references (in alias definitions bb writes them without CView)
    e = re.sub(r"(?<![$\w])(\w+)", lambda m: "$" + m.group(1) if m.group(1) in aliases else m.group(1), e)
    return e


def parse(expr_text):
    toks = []
    for m in TOKEN.finditer(expr_text):
        ident, const, op = m.groups()
        if ident:
            toks.append(("atom", ident))
        elif const:
            toks.append(("atom", const))
        elif op:
            if op not in "+-*()":
                fail(f"unexpected token {op!r} in {expr_text[:200]}")
            toks.append(("op", op))
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else (None, None)

    def primary():
        nonlocal pos
        kind, v = peek()
        if kind == "atom":
            pos += 1
            return v
        if v == "(":
            pos += 1
            node = additive()
            if peek() != ("op", ")"):
                fail(f"unbalanced parentheses in {expr_text[:200]}")
            pos += 1
            return node
        if v == "-":
            pos += 1
            return ("neg", primary())
        fail(f"unexpected {v!r} in {expr_text[:200]}")

    def multiplicative():
        nonlocal pos
        node = primary()
        while peek() == ("op", "*"):
            pos += 1
            node = ("*", node, primary())
        return node

    def additive():
        nonlocal pos
        node = multiplicative()
        while peek()[0] == "op" and peek()[1] in "+-":
            op = peek()[1]
            pos += 1
            node = (op, node, multiplicative())
        return node

    node = additive()
    if pos != len(toks):
        fail(f"trailing tokens in {expr_text[:200]}")
    return node


def sexpr(node):
    if isinstance(node, str):
        return node
    return "(" + " ".join([node[0]] + [sexpr(c) for c in node[1:]]) + ")"


def check_atoms(node, columns, aliases):
    if isinstance(node, str):
        if node.startswith("#"):
            return
        if node.startswith("$"):
            if node[1:] not in aliases:
                fail(f"unknown alias {node}")
            return
        if node not in columns:
            fail(f"unknown column {node}")
        return
    for c in node[1:]:
        check_atoms(c, columns, aliases)


def partial_lengths(hpp, class_name):
    text = hpp.read_text()
    m = re.search(
        rf"class {class_name}Impl \{{.*?SUBRELATION_PARTIAL_LENGTHS = \{{([^}}]*)\}}", text, re.S
    )
    if not m:
        fail(f"no SUBRELATION_PARTIAL_LENGTHS for {class_name}")
    return [int(x) for x in m.group(1).replace("\n", " ").split(",") if x.strip()]


def relation(name, columns):
    impl = (GEN / "relations" / f"{name}_impl.hpp").read_text()
    body = impl[impl.index("using C = ColumnAndShifts;") :]
    stmts = []
    aliases = set()
    first = re.search(r"\n\s*\{", body)
    first_block = first.start() if first else len(body)
    for m in re.finditer(r"const auto (\w+) =(.*?);", body, re.S):
        if m.start() > first_block:
            fail(f"{name}: alias {m.group(1)} defined after the first subrelation")
        expr = parse(normalize(m.group(2), aliases))
        check_atoms(expr, columns, aliases)
        aliases.add(m.group(1))
        stmts.append(f"let {m.group(1)} {sexpr(expr)}")
    blocks = list(
        re.finditer(
            r"auto tmp =(.*?);\s*std::get<(\d+)>\(evals\) \+= \(tmp \* scaling_factor\);", body, re.S
        )
    )
    if len(blocks) != body.count("std::get<"):
        fail(f"{name}: a subrelation does not have the `evals += tmp * scaling_factor` shape")
    for i, m in enumerate(blocks):
        if int(m.group(2)) != i:
            fail(f"{name}: subrelation {m.group(2)} out of order")
        expr = parse(normalize(m.group(1), aliases))
        check_atoms(expr, columns, aliases)
        stmts.append(f"sub {sexpr(expr)}")
    lengths = partial_lengths(GEN / "relations" / f"{name}.hpp", name)
    if len(lengths) != len(blocks):
        fail(f"{name}: {len(lengths)} partial lengths, {len(blocks)} subrelations")
    return lengths, stmts


def interactions(columns):
    found = {}
    for path in sorted((GEN / "relations").glob("lookups_*.hpp")) + sorted((GEN / "relations").glob("perms_*.hpp")):
        text = path.read_text()
        for m in re.finditer(r"struct (\w+)_settings_ \{(.*?)\n\};", text, re.S):
            body = m.group(2)

            def col(field):
                f = re.search(rf"static constexpr Column {field} =\s*Column::(\w+);", body)
                return f.group(1) if f else None

            def cols(field):
                f = re.search(rf"std::array<ColumnAndShifts, \w+> {field} = \{{(.*?)\}};", body, re.S)
                return re.findall(r"ColumnAndShifts::(\w+)", f.group(1))

            entry = {
                "src_sel": col("SRC_SELECTOR"),
                "dst_sel": col("DST_SELECTOR"),
                "counts": col("COUNTS"),
                "inverses": col("INVERSES"),
                "src": cols("SRC_COLUMNS"),
                "dst": cols("DST_COLUMNS"),
            }
            for c in [entry["src_sel"], entry["dst_sel"], entry["inverses"]] + entry["src"] + entry["dst"]:
                if c not in columns:
                    fail(f"{m.group(1)}: unknown column {c}")
            if len(entry["src"]) != len(entry["dst"]):
                fail(f"{m.group(1)}: tuple sizes differ")
            found[m.group(1)] = entry
        for m in re.finditer(r"using (\w+)_relation =\s*(lookup|permutation)_relation_base<FF_, (\w+)_settings>;", text):
            if m.group(1) != m.group(3):
                fail(f"relation {m.group(1)} uses settings {m.group(3)}")
            found[m.group(1)]["kind"] = m.group(2)
    return found


def relation_order():
    text = (GEN / "flavor_variables.hpp").read_text()
    main = re.search(r"using MainRelations_ = flat_tuple::tuple<(.*?)>;", text, re.S).group(1)
    look = re.search(r"using LookupRelations_ = flat_tuple::tuple<(.*?)>;", text, re.S).group(1)
    return re.findall(r"avm2::(\w+)<FF_>", main), re.findall(r"(\w+)_relation<FF_>", look)


def main():
    pre, wires, derived, shifted = layout()
    columns = pre + wires + derived + shifted
    colset = set(columns)
    if len(colset) != len(columns):
        fail("duplicate column names")
    consts = constants()
    vk_hash, vk = fixed_vk(len(pre))
    main_rels, interaction_rels = relation_order()
    inter = interactions(colset)

    rel_lines = [
        "# AUTOGENERATED by dev/regen_avm.py from the pin's vm2/generated/ (bb-pilcom output). Do not edit.",
        "# relation <name> <partial lengths, one per subrelation>: `let` = an alias bb hoists above the",
        "# subrelations, `sub` = the next subrelation (accumulated times the scaling factor).",
        "# lookup|perm <name> <src_sel> <dst_sel> <inverses> [<counts>] : <src columns> : <dst columns>",
    ]
    max_len = 0
    num_sub = 0
    for name in main_rels:
        if name in HANDWRITTEN:
            hpp = VM2 / "optimized/relations/poseidon2_perm.hpp"
            lengths = partial_lengths(hpp, name)
            rel_lines.append(f"relation {name} {','.join(map(str, lengths))} handwritten")
        else:
            lengths, stmts = relation(name, colset)
            rel_lines.append(f"relation {name} {','.join(map(str, lengths))}")
            rel_lines.extend(stmts)
        max_len = max(max_len, *lengths)
        num_sub += len(lengths)
    for name in interaction_rels:
        e = inter.get(name)
        if e is None or "kind" not in e:
            fail(f"no settings for {name}")
        if e["kind"] == "lookup":
            if e["counts"] is None:
                fail(f"{name}: lookup without counts")
            head = f"lookup {name} {e['src_sel']} {e['dst_sel']} {e['inverses']} {e['counts']}"
            max_len = max(max_len, 5)
        else:
            if e["counts"] is not None:
                fail(f"{name}: permutation with counts")
            head = f"perm {name} {e['src_sel']} {e['dst_sel']} {e['inverses']}"
            max_len = max(max_len, 4)
        rel_lines.append(f"{head} : {' '.join(e['src'])} : {' '.join(e['dst'])}")
        num_sub += 2

    lay = [
        "# AUTOGENERATED by dev/regen_avm.py from the pin's AVM sources. Do not edit.",
        f"max_trace_log_size {consts['MAX_AVM_TRACE_LOG_SIZE']}",
        f"proof_length {consts['AVM_V2_PROOF_LENGTH_IN_FIELDS']}",
        "public_input_column_lengths " + " ".join(str(consts[f"AVM_PUBLIC_INPUTS_COLUMN_{i}_LENGTH"]) for i in range(4)),
        f"max_partial_length {max_len}",
        f"num_subrelations {num_sub}",
        f"counts {len(pre)} {len(wires)} {len(derived)} {len(shifted)}",
        f"vk_hash {vk_hash}",
    ]
    lay += [f"vk {p[0]} {p[1]}" if p else "vk infinity" for p in vk]
    lay += ["columns"] + columns

    OUT.mkdir(parents=True, exist_ok=True)
    for fname, lines in [("layout.txt", lay), ("relations.txt", rel_lines)]:
        path = OUT / fname
        new = "\n".join(lines) + "\n"
        old = path.read_text() if path.exists() else None
        if old != new:
            path.write_text(new)
            print(f"updated {path.relative_to(HERE)}")
    print(
        f"regen_avm: {len(main_rels)} relations + {len(interaction_rels)} interactions, "
        f"{num_sub} subrelations, {len(columns)} columns, max partial length {max_len}"
    )


main()
