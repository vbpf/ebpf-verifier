#include <string>
#include <array>
#include <map>
using std::string;
using std::array;
using std::map;

enum class RET {
    PTR_TO_MAP_VALUE_OR_NULL,
    INTEGER
};

enum class ARG {
    ANYTHING,
    CONST_SIZE,
    CONST_MAP_PTR,
    PTR_TO_MAP_KEY,
    PTR_TO_MAP_VALUE,
    PTR_TO_MAP_VALUE_OR_NULL,
    PTR_TO_UNINIT_MEM
};


struct sig {
    string name;
	RET ret;
    array<ARG, 6> args;
};

const map<int, sig> sigs = {
1,  sig{"map_lookup_elem",       RET::PTR_TO_MAP_VALUE_OR_NULL, { ARG::CONST_MAP_PTR,     ARG::PTR_TO_MAP_KEY} },
2,  sig{"map_update_elem",       RET::INTEGER,                  { ARG::CONST_MAP_PTR,     ARG::PTR_TO_MAP_KEY, ARG::PTR_TO_MAP_VALUE, ARG::ANYTHING} },
3,  sig{"map_delete_elem",       RET::INTEGER,                  { ARG::CONST_MAP_PTR,     ARG::PTR_TO_MAP_KEY} },
4,  sig{"get_prandom_u32",       RET::INTEGER, {} },
5,  sig{"get_smp_processor_id",  RET::INTEGER, {} },
6,  sig{"get_numa_node_id",      RET::INTEGER, {} },
7,  sig{"ktime_get_ns",          RET::INTEGER, {} },
8,  sig{"get_current_pid_tgid",  RET::INTEGER, {} },
9,  sig{"get_current_uid_gid",   RET::INTEGER, {} },
10, sig{"get_current_comm",      RET::INTEGER,                   { ARG::PTR_TO_UNINIT_MEM, ARG::CONST_SIZE} },
11, sig{"get_current_cgroup_id", RET::INTEGER, {} }
};