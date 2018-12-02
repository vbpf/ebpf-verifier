#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <optional>
#include <iostream>

#include "asm.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;

static auto get_jump(Instruction ins, pc_t pc) -> optional<Label>
{
    if (std::holds_alternative<Jmp>(ins)) {
        return std::get<Jmp>(ins).target;
    }
    return {};
}

static auto get_fall(Instruction ins, pc_t pc) -> optional<Label>
{
    if (std::holds_alternative<Bin>(ins)
        && std::get<Bin>(ins).lddw)
        return std::to_string(pc + 2);

    if (std::holds_alternative<Exit>(ins))
        return {};
    if (std::holds_alternative<Undefined>(ins))
        return {};

    if (std::holds_alternative<Jmp>(ins)
        && !std::get<Jmp>(ins).cond)
            return {};

    return std::to_string(pc + 1);
}

static void link(Cfg& cfg, Label from, optional<Label> to) {
    if (to) {
        cfg[from].nextlist.push_back(*to);
        cfg[*to].prevlist.push_back(from);
    }
}

Cfg build_cfg(const Program& prog)
{
    Cfg cfg;
    for (pc_t pc = 0; pc < prog.code.size(); pc++) {
        Instruction ins = prog.code[pc];
        Label label = std::to_string(pc);
        if (std::holds_alternative<Undefined>(ins))
            continue;
        // create if not exists
        cfg[label].insts = {ins};

        link(cfg, label, get_fall(ins, pc));
        link(cfg, label, get_jump(ins, pc));
    }
    return cfg;
}

void print_stats(const Program& prog) {
    Cfg cfg = build_cfg(prog);
    auto& insts = prog.code;
    int count = 0;
    int stores = 0;
    int loads = 0;
    int jumps = 0;
    int joins = 0;
    vector<int> reaching(insts.size());
    for (auto const& [this_label, bb] : cfg) {
        Instruction ins = bb.insts[0];
        count++;
        if (std::holds_alternative<Mem>(ins)) {
            auto mem = std::get<Mem>(ins);
            if (mem.isLoad())
                loads++;
            else
                stores++;
        }
        if (bb.prevlist.size() > 1)
            joins++;
        if (bb.nextlist.size() > 1)
            jumps++;
    }
    std::cout << "instructions:" << count << "\n";
    std::cout << "loads:" << loads << "\n";
    std::cout << "stores:" << stores << "\n";
    std::cout << "jumps:" << jumps << "\n";
    std::cout << "joins:" << joins << "\n";
}
