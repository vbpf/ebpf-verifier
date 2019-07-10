#pragma once 

/*
 * Factories for variable names. 
 */

#include "crab/types.hpp"

#include <boost/optional.hpp>
#include <boost/noncopyable.hpp>
#include <boost/unordered_map.hpp>
#include <boost/range/iterator_range.hpp>

#include <limits>

namespace crab {
namespace cfg  {
namespace var_factory_impl {
namespace indexed_string_impl  {
  template<typename T>
  inline std::string get_str(T e);

  template<> inline std::string get_str(std::string e) { return e; }
} 

// This variable factory creates a new variable associated to an
// element of type T. It can also create variables that are not
// associated to an element of type T. We call them shadow variables.
// 
// The factory uses a counter of type index_t to generate variable
// id's that always increases.
template<class T>
class variable_factory : public boost::noncopyable {
  typedef variable_factory<T> variable_factory_t;
  
public:
  
  class indexed_string  {
    template<typename Any>
    friend class variable_factory;
    
  public:
    
    // FIXME: we should use some unlimited precision type to avoid
    // overflow. However, this change is a bit involving since we
    // need to change the algorithm api's in patricia_trees.hpp because
    // they assume ikos::index_t.
    typedef ikos::index_t index_t; 
    
  private:
    boost::optional<T> _s;
    index_t _id;
    std::string _name; // optional string name associated with _id
    variable_factory* _vfac;
    
    // NOT IMPLEMENTED
    indexed_string();
    
    indexed_string(index_t id, variable_factory *vfac, std::string name = "")
      : _id(id), _name(name), _vfac(vfac) { } 
	   
    indexed_string(T s, index_t id, variable_factory *vfac)
      : _s(s), _id(id), _name(""), _vfac(vfac) { }
      
  public:
    
    ~indexed_string() {}
    
    indexed_string(const indexed_string& is)
      : _s(is._s), _id(is._id), _name(is._name), _vfac(is._vfac) { }
    
    indexed_string& operator=(const indexed_string& is) {
      if (this != &is) {
	_s = is._s;
	_id = is._id;
	_name = is._name;
	_vfac = is._vfac;
      }
      return *this;
    }
    
    index_t index() const { return this->_id; }
    
    std::string str() const {
      if (_s) {
	return indexed_string_impl::get_str<T>(*_s);
      } else {
	if (_name != "") {
	  return _name;
	} else {
	  // unlikely prefix
	  return "@V_" + std::to_string(_id);
	}
      }
    }
    
    boost::optional<T> get() const{
      return _s ? *_s : boost::optional<T>();
    }
    
    variable_factory& get_var_factory() { return *_vfac; }
    
    bool operator<(indexed_string s)  const 
    { return (_id < s._id); }
    
    bool operator==(indexed_string s) const 
    { return (_id == s._id);}
    
    void write(crab_os& o) const
    { o << str(); }
    
    friend crab_os& operator<<(crab_os& o, indexed_string s) {
      o << s.str();
      return o;
    }
    
    friend size_t hash_value(indexed_string  s) {
      boost::hash<index_t> hasher;
      return hasher(s.index());
    }
  }; 
  
public:
  
  typedef typename indexed_string::index_t index_t;
  
private:
  
  typedef boost::unordered_map<T, indexed_string>  t_map_t;      
  typedef boost::unordered_map<index_t, indexed_string> shadow_map_t;      
  
  index_t _next_id;
  t_map_t _map;
  shadow_map_t _shadow_map;
  std::vector<indexed_string> _shadow_vars;

  index_t get_and_increment_id(void) {
    if (_next_id == std::numeric_limits<index_t>::max()) {
      CRAB_ERROR("Reached limit of ", std::numeric_limits<index_t>::max(),
		 " variables"); 
    }
    index_t res = _next_id;
    ++_next_id;
    return res;
  }
  
public:
  
  typedef indexed_string varname_t;
  typedef boost::iterator_range
  <typename std::vector<indexed_string>::iterator> var_range;
  typedef boost::iterator_range
  <typename std::vector<indexed_string>::const_iterator> const_var_range;
  
public:
  
  variable_factory(): _next_id(1) {}
  
  variable_factory(index_t start_id): _next_id(start_id) { }
  
  virtual ~variable_factory() {}
  
  // hook for generating indexed_string's without being
  // associated with a particular T (w/o caching).
  // XXX: do not use it unless strictly necessary.
  virtual indexed_string get() {
    indexed_string is(get_and_increment_id(), this);
    _shadow_vars.push_back(is);
    return is;
  }
  
  // generate a shadow indexed_string's associated to some key
  virtual indexed_string get(index_t key, std::string name = "") {
    auto it = _shadow_map.find(key);
    if (it == _shadow_map.end()) {
      indexed_string is(get_and_increment_id(), this, name);
      _shadow_map.insert(typename shadow_map_t::value_type(key, is));
      _shadow_vars.push_back(is);
      return is;
    } else {
      return it->second;
    }
  }
  
  virtual indexed_string operator[](T s) {
    auto it = _map.find(s);
    if (it == _map.end()) { 
      indexed_string is(s, get_and_increment_id(), this);
      _map.insert(typename t_map_t::value_type(s, is));
      return is;
    } else  {
      return it->second;
    }
  }
  
  // return all the shadow variables created by the factory.
  virtual const_var_range get_shadow_vars() const {
    return boost::make_iterator_range(_shadow_vars.begin(),
				      _shadow_vars.end());
  }
  
}; 

//! Specialized factory for strings
class str_variable_factory : public variable_factory<std::string> {
  typedef variable_factory<std::string> variable_factory_t;
public: 
  
  typedef variable_factory_t::varname_t varname_t;
  typedef variable_factory_t::const_var_range const_var_range;
  typedef variable_factory_t::index_t index_t;         
  
  str_variable_factory(): variable_factory_t() { }
}; 

//! Specialized factory for integers
class int_variable_factory : public boost::noncopyable { 
public: 
  typedef int varname_t;
  
  int_variable_factory() { }
  
  varname_t operator[](int v) { return v; }
}; 

inline int fresh_colour(int col_x, int col_y) {
  switch(col_x) {
  case 0: return col_y == 1 ? 2 : 1;
  case 1: return col_y == 0 ? 2 : 0;
  case 2: return col_y == 0 ? 1 : 0;
  default: CRAB_ERROR("Unreachable");
  }
}

//! Three-coloured variable allocation. So the number of variables
//  is bounded by 3|Tbl|, rather than always increasing.
class str_var_alloc_col {
  static const char** col_prefix;
public:
  
  typedef str_variable_factory::varname_t varname_t;
  static str_variable_factory vfac;
  
  str_var_alloc_col()
    : colour(0), next_id(0)
  { }
  
  str_var_alloc_col(const str_var_alloc_col& o)
    : colour(o.colour), next_id(o.next_id)
  { }
  
  str_var_alloc_col(const str_var_alloc_col& x, const str_var_alloc_col& y)
    : colour(fresh_colour(x.colour, y.colour)),
      next_id(0) {
    assert(colour != x.colour);
    assert(colour != y.colour);
  }
  
  str_var_alloc_col& operator=(const str_var_alloc_col& x) {
    colour = x.colour;
    next_id = x.next_id;
    return *this;
  }
  
  str_variable_factory::varname_t next() {
    std::string v = col_prefix[colour] + std::to_string(next_id++);
    return vfac[v];
  }
  
protected:
  int colour;
  int next_id;
};


class int_var_alloc_col {
public:
  typedef int varname_t;
  static int_variable_factory vfac;
  
  int_var_alloc_col()
    : colour(0), next_id(0)
  { }
  
  int_var_alloc_col(const int_var_alloc_col& o)
    : colour(o.colour), next_id(o.next_id)
  { }
  
  int_var_alloc_col(const int_var_alloc_col& x, const int_var_alloc_col& y)
    : colour(fresh_colour(x.colour, y.colour)),
      next_id(0) {
    assert(colour != x.colour);
    assert(colour != y.colour);
  }
         
  int_var_alloc_col& operator=(const int_var_alloc_col& x) {
    colour = x.colour;
    next_id = x.next_id;
    return *this;
  }
  
  int_variable_factory::varname_t next() {
    int id = next_id++;
    return 3*id + colour;
  }
  
protected:
  int colour;
  int next_id;
};

} // end namespace var_factory_impl
} // end namespace cfg
} // end namespace crab

