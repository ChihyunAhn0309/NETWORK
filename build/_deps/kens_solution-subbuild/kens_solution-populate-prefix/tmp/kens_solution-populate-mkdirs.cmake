# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/workspace/build/_deps/kens_solution-src"
  "/workspace/build/_deps/kens_solution-build"
  "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix"
  "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/tmp"
  "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/src/kens_solution-populate-stamp"
  "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/src"
  "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/src/kens_solution-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/src/kens_solution-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/workspace/build/_deps/kens_solution-subbuild/kens_solution-populate-prefix/src/kens_solution-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
