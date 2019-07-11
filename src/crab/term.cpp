#include "crab/var_factory.hpp"

namespace crab {
  namespace cfg {
     namespace var_factory_impl {
       str_variable_factory str_var_alloc_col::vfac;
       static const char* col_prefix_data[] = { "_x", "_y", "_z" };
       const char** str_var_alloc_col::col_prefix = col_prefix_data;
     }
  }
}
