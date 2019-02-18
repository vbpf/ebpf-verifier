#pragma once
// from https://stackoverflow.com/a/671389/2289509

#include <unistd.h>
#include <ios>
#include <iostream>
#include <fstream>
#include <string>

inline long resident_set_size_kb()
{
   std::string _;
   unsigned long __;
   long rss;
   {
        std::ifstream stat_stream("/proc/self/stat",std::ios_base::in);
        stat_stream >> _ >> _ >> _ >> _ >> _ >> _ >> _
                    >> _ >> _ >> _ >> _ >> _ >> _
                    >> _ >> _ >> _ >> _ >> _ >> _
                    >> _ >> _ >> _ >> __ >> rss; // don't care about the rest
   }

   long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
   return rss * page_size_kb;
}
