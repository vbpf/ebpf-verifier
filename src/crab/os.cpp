#include "crab/os.hpp"

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <iostream>
#include <sstream>

namespace crab 
{
  crab_os& outs () { return *crab_os::cout();}
  crab_os& errs () { return *crab_os::cerr();}
}

namespace crab {

  /// crab_os adaptor

  boost::shared_ptr<crab_os> crab_os::m_cout = nullptr;

  boost::shared_ptr<crab_os> crab_os::m_cerr = nullptr;

  boost::shared_ptr<crab_os> crab_os::cout() {
    if (!m_cout) m_cout = boost::make_shared<crab_os>(&std::cout);
    return m_cout;
  }

  boost::shared_ptr<crab_os> crab_os::cerr() {
    if (!m_cerr) m_cerr = boost::make_shared<crab_os>(&std::cerr);
    return m_cerr;
  }

  crab_os::crab_os(std::ostream* os): m_os(os) { }

  crab_os::crab_os(): m_os(nullptr) {}

  crab_os::~crab_os() { }
  
  crab_os& crab_os::operator<<(char C) {
    *m_os << C; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(unsigned char C) {
    *m_os << C; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(signed char C) {
    *m_os << C; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(const char* C) {
    *m_os << C; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(const std::string& Str) {
    *m_os << Str; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(unsigned long N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(long N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(unsigned long long N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(long long N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(const void *P) {
    *m_os << P; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(unsigned int N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(int N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  crab_os& crab_os::operator<<(double N) {
    *m_os << N; m_os->flush ();
    return *this;
  }

  /// crab_string_os adaptor

  crab_string_os::crab_string_os ()
      : crab_os(), m_string_os(new std::ostringstream()) { }

  crab_string_os::~crab_string_os() {
    delete m_string_os;
  }

  crab_os& crab_string_os::operator<<(char C) {
    *m_string_os << C;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(unsigned char C){
    *m_string_os << C;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(signed char C){
    *m_string_os << C;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(const char *Str){
    *m_string_os << Str;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(const std::string& Str){  
    *m_string_os << Str;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(unsigned long N) {
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(long N) {
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(unsigned long long N){
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }  

  crab_os& crab_string_os::operator<<(long long N){
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(const void *P){
    *m_string_os << P;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(unsigned int N){
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(int N){
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  crab_os& crab_string_os::operator<<(double N) {
    *m_string_os << N;
    return *(static_cast<crab_os*>(this));
  }

  std::string crab_string_os::str() {
    return m_string_os->str();
  }

} // end namespace
