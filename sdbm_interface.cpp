
class Number;
class VariableName;
class Params = DBM_impl::DefaultParams<Number>>;

class SplitDBM final : public abstract_domain<SplitDBM<Number, VariableName, Params>> {
public:
  SplitDBM(bool is_bottom = false);
  SplitDBM(const DBM_t& o);
  SplitDBM(DBM_t&& o);

  SplitDBM(vert_map_t&  _vert_map, rev_map_t&  _rev_map, graph_t&  _g, std::vector<Wt>&  _potential, vert_set_t&  _unstable);
  SplitDBM(vert_map_t&& _vert_map, rev_map_t&& _rev_map, graph_t&& _g, std::vector<Wt>&& _potential, vert_set_t&& _unstable);

  SplitDBM& operator=(const SplitDBM&  o);
  SplitDBM& operator=(      SplitDBM&& o);

  void set_to_top();
  void set_to_bottom();
  bool is_bottom();
  bool is_top();

  bool operator<=(DBM_t o);

  void operator|=(DBM_t o);
  void operator&=(DBM_t o);

  DBM_t widening_thresholds(DBM_t o, const iterators::thresholds<number_t> &ts) ;

  void normalize();
  void minimize();

  void operator-=(variable_t v);

  void assign(variable_t x, linear_expression_t e);

  void apply(operation_t op, variable_t x, variable_t y, variable_t z);
  void apply(operation_t op, variable_t x, variable_t y, number_t k);

  void backward_assign(variable_t x, linear_expression_t e, DBM_t inv);

  void backward_apply(operation_t op, variable_t x, variable_t y, number_t   z, DBM_t inv);
  void backward_apply(operation_t op, variable_t x, variable_t y, variable_t z, DBM_t inv);

  void operator+=(linear_constraint_t cst);
  void operator+=(linear_constraint_system_t csts);

  interval_t operator[](variable_t x);

  void set(variable_t x, interval_t intv);

  void apply(int_conv_operation_t op, variable_t dst, variable_t src);

  void apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z);
  void apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k);

  void project(const variable_vector_t &variables);

  void forget(const variable_vector_t &variables);

  void expand(variable_t x, variable_t y);

  void rename(const variable_vector_t& from, const variable_vector_t& to) ;

  void extract(const variable_t& x, linear_constraint_system_t& csts, bool only_equalities);

  bool is_unsat_without_modfication(linear_constraint_t cst);
  void active_variables(std::vector<variable_t>& out) const;

  // Output function
  void write(crab_os &o);

  linear_constraint_system_t to_linear_constraint_system();
  disjunctive_linear_constraint_system_t to_disjunctive_linear_constraint_system() ;

  // return number of vertices and edges
  std::pair<std::size_t, std::size_t> size() const;

  static std::string getDomainName();
};
