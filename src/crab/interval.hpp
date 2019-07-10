/*******************************************************************************
 * 
 * A simple class for representing intervals and performing interval
 * arithmetic.
 * 
 ******************************************************************************/

#pragma once

#include <boost/optional.hpp>
#include "crab/types.hpp"
#include "crab/stats.hpp"
#include "crab/bignums.hpp"
#include "crab/linear_interval_solver.hpp"

namespace ikos {

  template<typename Number>
  class bound {
  public:
    typedef bound<Number> bound_t;
    
  private:
    bool _is_infinite;
    Number _n;

  private:
    bound();
    
    bound(bool is_infinite, Number n): _is_infinite(is_infinite), _n(n) {
      if (is_infinite){
        if (n > 0)
          _n = 1;
        else 
          _n = -1;
      }
    }
    
  public:
    static bound_t min(bound_t x, bound_t y) {
      return (x.operator<=(y) ? x : y);
    }

    static bound_t min(bound_t x, bound_t y, bound_t z) {
      return min(x, min(y, z));
    }

    static bound_t min(bound_t x, bound_t y, bound_t z, bound_t t) {
      return min(x, min(y, z, t));
    }

    static bound_t max(bound_t x, bound_t y) {
      return (x.operator<=(y) ? y : x);
    }

    static bound_t max(bound_t x, bound_t y, bound_t z) {
      return max(x, max(y, z));
    }

    static bound_t max(bound_t x, bound_t y, bound_t z, bound_t t) {
      return max(x, max(y, z, t));
    }

    static bound_t plus_infinity() {
      return bound_t(true, 1);
    }
    
    static bound_t minus_infinity() {
      return bound_t(true, -1);
    }
    
  public:
    bound(int n): _is_infinite(false), _n(n) { }

    bound(std::string s): _n(1) {
      if (s == "+oo") {
        _is_infinite = true;
      } else if (s == "-oo") {
        _is_infinite = true;
        _n = -1;
      } else {
        _is_infinite = false;
        _n = Number(s);
      }
    }

    bound(Number n): _is_infinite(false), _n(n) { }
    
    bound(const bound_t& o): _is_infinite(o._is_infinite), _n(o._n) { }
    
    bound_t& operator=(const bound_t &o){
      if (this != &o) {
        _is_infinite = o._is_infinite;
        _n = o._n;
      }
      return *this;
    }
    
    bool is_infinite() const {
      return _is_infinite;
    }
    
    bool is_finite() const {
      return !_is_infinite;
    }

    bool is_plus_infinity() const {
      return (is_infinite() && _n > 0);
    }
    
    bool is_minus_infinity() const {
      return (is_infinite() && _n < 0);
    }
    
    bound_t operator-() const {
      return bound_t(_is_infinite, -_n);
    }
    
    bound_t operator+(bound_t x) const {
      if (is_finite() && x.is_finite()) {
        return bound_t(_n + x._n);
      } else if (is_finite() && x.is_infinite()) {
        return x;
      } else if (is_infinite() && x.is_finite()) {
        return *this;
      } else if (_n == x._n) {
        return *this;
      } else {
        CRAB_ERROR("Bound: undefined operation -oo + +oo");
      }
    }

    bound_t& operator+=(bound_t x)  {
      return operator=(operator+(x));
    }
		
    bound_t operator-(bound_t x) const {
      return operator+(x.operator-());
    }
		
    bound_t& operator-=(bound_t x)  {
      return operator=(operator-(x));
    }
    
    bound_t operator*(bound_t x) const {
      if (x._n == 0) 
        return x;
      else if (_n == 0)
        return *this;
      else 
        return bound_t(_is_infinite || x._is_infinite, _n * x._n);
    }
		
    bound_t& operator*=(bound_t x)  {
      return operator=(operator*(x));
    }
    
    bound_t operator/(bound_t x) const {
      if (x._n == 0) {
        CRAB_ERROR("Bound: division by zero");
      } else if (is_finite() && x.is_finite()) {
        return bound_t(false, _n / x._n);
      } else if (is_finite() && x.is_infinite()) {
        if (_n > 0) {
          return x;
        } else if (_n == 0) {
          return *this;
        } else {
          return x.operator-();
        }
      } else if (is_infinite() && x.is_finite()) {
        if (x._n > 0) {
          return *this;
        } else {
          return operator-();
        }
      } else {
        return bound_t(true, _n * x._n);
      }
    }
    
    bound_t& operator/=(bound_t x) {
      return operator=(operator/(x));
    }
    
    bool operator<(bound_t x) const {
      return !operator>=(x);
    }

    bool operator>(bound_t x) const {
      return !operator<=(x);
    }

    bool operator==(bound_t x) const {
      return (_is_infinite == x._is_infinite && _n == x._n);
    }
    
    bool operator!=(bound_t x) const {
      return !operator==(x);
    }
    
    /*	operator<= and operator>= use a somewhat optimized implementation.
     *	results include up to 20% improvements in performance in the octagon domain
     *	over a more naive implementation.
     */
    bool operator<=(bound_t x) const {
      if(_is_infinite xor x._is_infinite){
        if(_is_infinite){
          return _n < 0;
        }
        return x._n > 0;
      }
      return _n <= x._n;
    }
    
    bool operator>=(bound_t x) const {
      if(_is_infinite xor x._is_infinite){
        if(_is_infinite){
          return _n > 0;
        }
        return x._n < 0;
      }
      return _n >= x._n;
    }
    
    bound_t abs() const {
      if (operator>=(0)) {
        return *this;
      } else {
        return operator-();
      }
    }
    
    boost::optional<Number> number() const {
      if (is_infinite()) {
        return boost::optional<Number>();
      } else {
        return boost::optional<Number>(_n);
      }
    }
    
    void write(crab::crab_os& o) const {
      if (is_plus_infinity()) {
        o << "+oo";
      } else if (is_minus_infinity()) {
        o << "-oo";
      } else {
        o << _n;
      }
    }
    
  }; // class bound

  template<typename Number>
  inline crab::crab_os& operator<<(crab::crab_os& o, const bound<Number> &b) {
    b.write(o);
    return o;
  }

  typedef bound<z_number> z_bound;
  typedef bound<q_number> q_bound;

  namespace bounds_impl {
    // Conversion between z_bound and q_bound
    // template<class B1, class B2>
    // inline void convert_bounds(B1 b1, B2& b2);
    
    inline void convert_bounds(z_bound b1, z_bound &b2)
    { std::swap (b1,b2); }
    inline void convert_bounds(q_bound b1, q_bound &b2)
    { std::swap (b1,b2); }
    inline void convert_bounds(z_bound b1, q_bound &b2)
    {
      if (b1.is_plus_infinity())
	b2 = q_bound::plus_infinity();
      else if (b1.is_minus_infinity())
	b2 = q_bound::minus_infinity();
      else
	b2 = q_bound (q_number(*b1.number()));
    }
    inline void convert_bounds(q_bound b1, z_bound &b2)
    {
      if (b1.is_plus_infinity())
	b2 = z_bound::plus_infinity();
      else if (b1.is_minus_infinity())
	b2 = z_bound::minus_infinity();
      else
	b2 = z_bound ((*(b1.number())).round_to_lower ());
    }
  }

  
  template<typename Number>
  class interval {
    
  public:
    typedef bound<Number> bound_t;
    typedef interval<Number> interval_t;
    
  private:
    bound_t _lb;
    bound_t _ub;

  public:
    static interval_t top() {
      return interval_t(bound_t::minus_infinity(), bound_t::plus_infinity());
    }

    static interval_t bottom() {
      return interval_t();
    }

  private:
    interval(): _lb(0), _ub(-1) { }

    static Number abs(Number x) { return x < 0 ? -x : x; }
    
    static Number max(Number x, Number y) { return x.operator<=(y) ? y : x; }
    
    static Number min(Number x, Number y) { return x.operator<(y) ? x : y; }
    
  public:
    interval(bound_t lb, bound_t ub): _lb(lb), _ub(ub) { 
      if (lb > ub) {
        _lb = 0;
        _ub = -1;
      }
    }
    
    interval(bound_t b): _lb(b), _ub(b) { 
      if (b.is_infinite()) {
        _lb = 0;
        _ub = -1;	
      }
    }

    interval(Number n): _lb(n), _ub(n) { }

    interval(std::string b): _lb(b), _ub(b) { 
      if (_lb.is_infinite()) {
        _lb = 0;
        _ub = -1;	
      }
    }

    interval(const interval_t& i): _lb(i._lb), _ub(i._ub) { }
    
    interval_t& operator=(interval_t i){
      _lb = i._lb;
      _ub = i._ub;
      return *this;
    }

    bound_t lb() const {
      return _lb;
    }

    bound_t ub() const {
      return _ub;
    }

    bool is_bottom() const {
      return (_lb > _ub);
    }
    
    bool is_top() const {
      return (_lb.is_infinite() && _ub.is_infinite());
    }
    
    interval_t lower_half_line() const {
      return interval_t(bound_t::minus_infinity(), _ub);
    }
    
    interval_t upper_half_line() const {
      return interval_t(_lb, bound_t::plus_infinity());
    }

    bool operator==(interval_t x) const {
      if (is_bottom()) {
        return x.is_bottom();
      } else {
        return (_lb == x._lb) && (_ub == x._ub);
      }
    }
    
    bool operator!=(interval_t x) const {
      return !operator==(x);
    }

    bool operator<=(interval_t x) const {
      if (is_bottom()) {
        return true;
      } else if (x.is_bottom()) {
        return false;
      } else {
        return (x._lb <= _lb) && (_ub <= x._ub);
      }
    }

    interval_t operator|(interval_t x) const {
      if (is_bottom()) {
        return x;
      } else if (x.is_bottom()) {
        return *this;
      } else {
	return interval_t(bound_t::min(_lb, x._lb), 
                            bound_t::max(_ub, x._ub));
      }
    }

    interval_t operator&(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return interval_t(bound_t::max(_lb, x._lb), 
                          bound_t::min(_ub, x._ub));
      }
    }
    
    interval_t operator||(interval_t x) const {
      if (is_bottom()) {
	return x;
      } else if (x.is_bottom()) {
	return *this;
      } else {
        return interval_t(x._lb < _lb ? 
                          bound_t::minus_infinity() : 
                          _lb, 
                          _ub < x._ub ?
                          bound_t::plus_infinity() : 
                          _ub);
      }
    }

    template<typename Thresholds>
    interval_t widening_thresholds (interval_t x, const Thresholds &ts) {
      if (is_bottom()) {
	return x;
      } else if (x.is_bottom()) {
	return *this;
      } else {
        bound_t lb = (x._lb < _lb ? ts.get_prev (x._lb) : _lb);
        bound_t ub = (_ub < x._ub ? ts.get_next (x._ub) :  _ub);            
        return interval_t(lb, ub);
      }
    }

    interval_t operator&&(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return interval_t(_lb.is_infinite() && x._lb.is_finite() ? 
                          x._lb : _lb, 
                          _ub.is_infinite() && x._ub.is_finite() ?
                          x._ub : _ub);
      }
    }

    interval_t operator+(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
	return interval_t(_lb + x._lb, _ub + x._ub);
      }
    }
    
    interval_t& operator+=(interval_t x) {
      return operator=(operator+(x));
    }
    
    interval_t operator-() const {
      if (is_bottom()) {
        return bottom();
      } else {
        return interval_t(-_ub, -_lb);
      }
    }
    
    interval_t operator-(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return interval_t(_lb - x._ub, _ub - x._lb);
      }
    }
    
    interval_t& operator-=(interval_t x) {
      return operator=(operator-(x));
    }
    
    interval_t operator*(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        bound_t ll = _lb * x._lb;
        bound_t lu = _lb * x._ub;
        bound_t ul = _ub * x._lb;
        bound_t uu = _ub * x._ub;
        return interval_t(bound_t::min(ll, lu, ul, uu), 
                          bound_t::max(ll, lu, ul, uu));
      }
    }
    
    interval_t& operator*=(interval_t x) {
      return operator=(operator*(x));
    }
    
    interval_t operator/(interval_t x) const;

    interval_t& operator/=(interval_t x) {
      return operator=(operator/(x));
    }   
    
    boost::optional<Number> singleton() const {
      if (!is_bottom() && _lb == _ub) {
        return _lb.number();
      } else {
        return boost::optional<Number>();
      }
    }
    
    bool operator[](Number n) const {
      if (is_bottom()) {
        return false;
      } else {
        bound_t b(n);
        return (_lb <= b) && (b <= _ub);
      }
    }
    
    void write(crab::crab_os& o) const {
      if (is_bottom()) {
        o << "_|_";
      } else {
        o << "[" << _lb << ", " << _ub << "]";
      }
    }    
    
    // division and remainder operations

    interval_t UDiv(interval_t x ) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }

    interval_t SRem(interval_t x)  const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }

    interval_t URem(interval_t x)  const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }

    // bitwise operations
    interval_t And(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }
    
    interval_t Or(interval_t x)  const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }
    
    interval_t Xor(interval_t x) const { return Or(x); }
    
    interval_t Shl(interval_t x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }

    interval_t LShr(interval_t  x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }

    interval_t AShr(interval_t  x) const {
      if (is_bottom() || x.is_bottom()) {
        return bottom();
      } else {
        return top();
      }
    }
    
  };//  class interval

  template<>
  inline interval<q_number> interval<q_number>::
  operator/(interval<q_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      boost::optional<q_number> d = x.singleton();
      if (d && *d == 0) {
        // [_, _] / 0 = _|_
        return bottom();
      } else if (x[0]) {
        boost::optional<q_number> n = singleton();
        if (n && *n == 0) {
          // 0 / [_, _] = 0
          return interval_t(q_number(0));
        } else {
          return top();
        }
      } else {
        bound_t ll = _lb / x._lb;
        bound_t lu = _lb / x._ub;
        bound_t ul = _ub / x._lb;
        bound_t uu = _ub / x._ub;
        return interval_t(bound_t::min(ll, lu, ul, uu), 
                          bound_t::max(ll, lu, ul, uu));
      }
    }
  }

  template<>
  inline interval<z_number> interval<z_number>::
  operator/(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      // Divisor is a singleton:
      //   the linear interval solver can perform many divisions where
      //   the divisor is a singleton interval. We optimize for this case.
      if (boost::optional<z_number> n = x.singleton()) {
	z_number c = *n;
	if (c == 1) {
	  return *this;
	} else if (c > 0) {
	  return interval_t(_lb / c, _ub / c);
	} else if (c < 0) {
	  return interval_t(_ub / c, _lb / c);
	} else {}
      }
      // Divisor is not a singleton
      typedef interval<z_number> z_interval;
      if (x[0]) {
        z_interval l(x._lb, z_bound(-1));
        z_interval u(z_bound(1), x._ub);
        return (operator/(l) | operator/(u));
      } else if (operator[](0)) {
        z_interval l(_lb, z_bound(-1));
        z_interval u(z_bound(1), _ub);
        return ((l / x) | (u / x) | z_interval(z_number(0)));
      } else {
        // Neither the dividend nor the divisor contains 0
        z_interval a = (_ub < 0) ? 
            (*this + ((x._ub < 0) ? 
                      (x + z_interval(z_number(1))) : 
                      (z_interval(z_number(1)) - x))) : *this;
	bound_t ll = a._lb / x._lb;
	bound_t lu = a._lb / x._ub;
	bound_t ul = a._ub / x._lb;
	bound_t uu = a._ub / x._ub;
	return interval_t(bound_t::min(ll, lu, ul, uu), 
			  bound_t::max(ll, lu, ul, uu));	
      }
    }
  }


  template <>
  inline interval<z_number> interval<z_number>::
  SRem(interval<z_number> x) const {
    // note that the sign of the divisor does not matter
    
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else if (singleton() && x.singleton()) {
      z_number dividend = *singleton();
      z_number divisor = *x.singleton();
      
      if (divisor == 0) {
        return bottom();
      }
      
      return interval_t(dividend % divisor);
    } else if (x.ub().is_finite() && x.lb().is_finite()) {
      z_number max_divisor = max(abs(*x.lb().number()), 
                                 abs(*x.ub().number()));
      
      if (max_divisor == 0) {
        return bottom();
      }
      
      if (lb() < 0) {
        if (ub() > 0) {
          return interval_t(-(max_divisor - 1), max_divisor - 1);
        } else {
          return interval_t(-(max_divisor - 1), 0);
        }
      } else {
        return interval_t(0, max_divisor - 1);
      }
    } else {
      return top();
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  URem(interval<z_number> x) const {
    
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else if (singleton() && x.singleton()) {
      z_number dividend = *singleton();
      z_number divisor = *x.singleton();
      
      if (divisor < 0) {
        return top();
      } else if (divisor == 0) {
        return bottom();
      } else if (dividend < 0) {
        // dividend is treated as an unsigned integer.
        // we would need the size to be more precise
        return interval_t(0, divisor - 1);
      } else {
        return interval_t(dividend % divisor);
      }
    } else if (x.ub().is_finite() && x.lb().is_finite()) {
      z_number max_divisor = *x.ub().number();
      
      if (x.lb() < 0 || x.ub() < 0) {
        return top();
      } else if (max_divisor == 0) {
        return bottom();
      }
      
      return interval_t(0, max_divisor - 1);
    } else {
      return top();
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  And(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      boost::optional<z_number > left_op = singleton();
      boost::optional<z_number > right_op = x.singleton();
      
      if (left_op && right_op) {
        return interval_t((*left_op) & (*right_op));
      } else if (lb() >= 0 && x.lb() >= 0) {
        return interval_t(0, bound_t::min(ub(), x.ub()));
      } else {
        return top();
      }
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  Or(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      boost::optional<z_number> left_op = singleton();
      boost::optional<z_number> right_op = x.singleton();
      
      if (left_op && right_op) {
        return interval_t((*left_op) | (*right_op));
      } else if (lb() >= 0 && x.lb() >= 0) {
        boost::optional<z_number> left_ub = ub().number();
        boost::optional<z_number> right_ub = x.ub().number();
        
        if (left_ub && right_ub) {
          z_number m = (*left_ub > *right_ub ? *left_ub : *right_ub); 
          return interval_t(0, m.fill_ones());
        } else {
          return interval_t(0, bound_t::plus_infinity());
        }
      } else {
        return top();
      }
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  Xor(interval<z_number> x)  const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      boost::optional<z_number> left_op = singleton();
      boost::optional<z_number> right_op = x.singleton();
      
      if (left_op && right_op) {
        return interval_t((*left_op) ^ (*right_op));
      } else {
        return Or(x);
      }
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  Shl(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      if (boost::optional<z_number> shift = x.singleton()) {
	z_number k = *shift;
	if (k < 0) {
	  //CRAB_ERROR("lshr shift operand cannot be negative");
	  return top();
	}
	// Some crazy linux drivers generate shl instructions with
	// huge shifts.  We limit the number of times the loop is run
	// to avoid wasting too much time on it.
	if (k <= 128) {
	  z_number factor = 1;
	  for (int i = 0; k > i ; i++) {
	    factor *= 2;
	  }
	  return (*this) * factor;
	}
      } 
      return top();
    }
  }

  template <>
  inline interval<z_number> interval<z_number>::
  AShr(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      if (boost::optional<z_number> shift = x.singleton()) {
	z_number k = *shift;
	if (k < 0) {
	  //CRAB_ERROR("ashr shift operand cannot be negative");
	  return top();
	}	  
	// Some crazy linux drivers generate ashr instructions with
	// huge shifts.  We limit the number of times the loop is run
	// to avoid wasting too much time on it.
	if (k <= 128) {
	  z_number factor = 1;
	  for (int i = 0; k > i; i++) {
	    factor *= 2;
	  }
	  return (*this) / factor;
	}
      }
      return top();
    }
  }
  
  template <>
  inline interval<z_number> interval<z_number>::
  LShr(interval<z_number> x) const {
    if (is_bottom() || x.is_bottom()) {
      return bottom();
    } else {
      if (boost::optional<z_number> shift = x.singleton()) {
	z_number k = *shift;
	if (k < 0) {
	  //CRAB_ERROR("lshr shift operand cannot be negative");
	  return top();
	}
	// Some crazy linux drivers generate lshr instructions with
	// huge shifts.  We limit the number of times the loop is run
	// to avoid wasting too much time on it.
	if (k <= 128) {
	  if (lb() >= 0 && ub().is_finite() && shift) {
	    z_number lb = *this->lb().number();
	    z_number ub = *this->ub().number();
	    return interval<z_number>(lb >> k, ub >> k);
	  }
	}
      }
      return this->top();
    }
  }

  template<typename Number>
  inline interval<Number> operator+(Number c, interval<Number> x) {
    return interval<Number>(c) + x;
  }
  
  template<typename Number>
  inline interval<Number> operator+(interval<Number> x, Number c) {
    return x + interval<Number>(c);
  }

  template<typename Number>
  inline interval<Number> operator*(Number c, interval<Number> x) {
    return interval<Number>(c) * x;
  }

  template<typename Number>
  inline interval<Number> operator*(interval<Number> x, Number c) {
    return x * interval<Number>(c);
  }

  template<typename Number>
  inline interval<Number> operator/(Number c, interval<Number> x) {
    return interval<Number>(c) / x;
  }

  template<typename Number>
  inline interval<Number> operator/(interval<Number> x, Number c) {
    return x / interval<Number>(c);
  }

  template<typename Number>
  inline interval<Number> operator-(Number c, interval<Number> x) {
    return interval<Number>(c) - x;
  }

  template<typename Number>
  inline interval<Number> operator-(interval<Number> x, Number c) {
    return x - interval<Number>(c);
  }

  template <typename Number>
  inline crab::crab_os& operator<<(crab::crab_os& o, const interval<Number>& i) {
    i.write(o);
    return o;
  }

  namespace linear_interval_solver_impl {

    typedef interval<z_number> z_interval;
    typedef interval<q_number> q_interval;  
    
    template<>
    inline z_interval trim_interval(z_interval i, z_interval j) {
      if (boost::optional<z_number> c = j.singleton()) {
	if (i.lb() == *c) {
	  return z_interval(*c + 1, i.ub());
	} else if (i.ub() == *c) {
	  return z_interval(i.lb(), *c - 1);
	} else {
	}	
      }
      return i;
    }
    
    template<>
    inline q_interval trim_interval(q_interval i, q_interval /* j */) { 
      // No refinement possible for disequations over rational numbers
      return i;
    }

    template<>
    inline z_interval lower_half_line(z_interval i, bool /*is_signed*/) {
      return i.lower_half_line();
    }

    template<>
    inline q_interval lower_half_line(q_interval i, bool /*is_signed*/) {
      return i.lower_half_line();
    }

    template<>
    inline z_interval upper_half_line(z_interval i, bool /*is_signed*/) {
      return i.upper_half_line();
    }

    template<>
    inline q_interval upper_half_line(q_interval i, bool /*is_signed*/) {
      return i.upper_half_line();
    }
  } // namespace linear_interval_solver_impl

} // namespace ikos



