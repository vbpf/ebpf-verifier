
#include "crab/safeint.hpp"
#include "crab/debug.hpp"

#include <limits>
#include <cstdint>

namespace crab {

int64_t safe_i64::get_max() const {
  return std::numeric_limits<int64_t>::max();
}

int64_t safe_i64::get_min() const {
  return std::numeric_limits<int64_t>::min();
}
  
int safe_i64::checked_add(int64_t a, int64_t b, int64_t *rp) const {
#if 1
  wideint_t lr = (wideint_t)a + (wideint_t)b;
  *rp = lr;
  return lr > get_max() || lr < get_min();
#else
  // without wider integers
  if (b > 0 && a > get_max() - b) {
    return 1;
  }
  if (b < 0 && a < get_min() - b) {
    return 1;
  }
  int64_t lr = a + b;
  *rp = lr;
  return 0;
#endif 
}
  
int safe_i64::checked_sub(int64_t a, int64_t b, int64_t *rp) const {
  wideint_t lr = (wideint_t)a - (wideint_t)b;
  *rp = lr;
  return lr > get_max() || lr < get_min();
}
  
int safe_i64::checked_mul(int64_t a, int64_t b, int64_t *rp) const {
  wideint_t lr = (wideint_t)a * (wideint_t)b;
  *rp = lr;
  return lr > get_max() || lr < get_min();
}
  
int safe_i64::checked_div(int64_t a, int64_t b, int64_t *rp) const {
  wideint_t lr = (wideint_t)a / (wideint_t)b;
  *rp = lr;
  return lr > get_max() || lr < get_min();
}
  
safe_i64::safe_i64(): m_num(0) {}
  
safe_i64::safe_i64(int64_t num): m_num(num) {}
  
safe_i64::safe_i64(ikos::z_number n): m_num((long) n) {}
  
safe_i64::operator long() const {
  return (long) m_num;
}

// FIXME: operation should not raise an error.
safe_i64 safe_i64::operator+(safe_i64 x) const {
  int64_t z;
  int err = checked_add(m_num, x.m_num, &z);
  if (err) {
    CRAB_ERROR("Integer overflow during addition");
  }
  return safe_i64(z);
}

// FIXME: operation should not raise an error.  
safe_i64 safe_i64::operator-(safe_i64 x) const {
  int64_t z;
  int err = checked_sub(m_num, x.m_num, &z);
  if (err) {
    CRAB_ERROR("Integer overflow during subtraction");
  }
  return safe_i64(z);
}

// FIXME: operation should not raise an error.  
safe_i64 safe_i64::operator*(safe_i64 x) const {
  int64_t z;
  int err = checked_mul(m_num, x.m_num, &z);
  if (err) {
    CRAB_ERROR("Integer overflow during multiplication");
  }
  return safe_i64(z);
}

// FIXME: operation should not raise an error.  
safe_i64 safe_i64::operator/(safe_i64 x) const {
  int64_t z;
  int err = checked_div(m_num, x.m_num, &z);
  if (err) {
    CRAB_ERROR("Integer overflow during multiplication");
  }
  return safe_i64(z);
}

// FIXME: operation should not raise an error.  
safe_i64 safe_i64::operator-() const {
  return safe_i64(0) - *this;
}

// FIXME: operation should not raise an error.  
safe_i64& safe_i64::operator+=(safe_i64 x) {
  int err = checked_add(m_num, x.m_num, &m_num);
  if (err) {
    CRAB_ERROR("Integer overflow during addition");
  }
  return *this;
}

// FIXME: operation should not raise an error.  
safe_i64& safe_i64::operator-=(safe_i64 x) {
  int err = checked_sub(m_num, x.m_num, &m_num);
  if (err) {
    CRAB_ERROR("Integer overflow during subtraction");
  }
  return *this;
}
  
bool safe_i64::operator==(safe_i64 x) const {
  return m_num == x.m_num;
}
  
bool safe_i64::operator!=(safe_i64 x) const {
  return m_num != x.m_num;
}
  
bool safe_i64::operator<(safe_i64 x) const {
  return m_num < x.m_num;
}
  
bool safe_i64::operator<=(safe_i64 x) const {
  return m_num <= x.m_num;
}

bool safe_i64::operator>(safe_i64 x) const {
  return m_num > x.m_num;
}
  
bool safe_i64::operator>=(safe_i64 x) const {
  return m_num >= x.m_num;
}
  
void safe_i64::write(crab::crab_os& os) const {
  os << m_num;
}
  
} // end namespace crab
