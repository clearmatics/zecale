# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/user99/Documents/antoine/dev/sc-zeth

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/user99/Documents/antoine/dev/sc-zeth/build

# Utility rule file for ExperimentalBuild.

# Include the progress variables for this target.
include src/CMakeFiles/ExperimentalBuild.dir/progress.make

src/CMakeFiles/ExperimentalBuild:
	cd /home/user99/Documents/antoine/dev/sc-zeth/build/src && /usr/bin/ctest -D ExperimentalBuild

ExperimentalBuild: src/CMakeFiles/ExperimentalBuild
ExperimentalBuild: src/CMakeFiles/ExperimentalBuild.dir/build.make

.PHONY : ExperimentalBuild

# Rule to build all files generated by this target.
src/CMakeFiles/ExperimentalBuild.dir/build: ExperimentalBuild

.PHONY : src/CMakeFiles/ExperimentalBuild.dir/build

src/CMakeFiles/ExperimentalBuild.dir/clean:
	cd /home/user99/Documents/antoine/dev/sc-zeth/build/src && $(CMAKE_COMMAND) -P CMakeFiles/ExperimentalBuild.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/ExperimentalBuild.dir/clean

src/CMakeFiles/ExperimentalBuild.dir/depend:
	cd /home/user99/Documents/antoine/dev/sc-zeth/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/user99/Documents/antoine/dev/sc-zeth /home/user99/Documents/antoine/dev/sc-zeth/src /home/user99/Documents/antoine/dev/sc-zeth/build /home/user99/Documents/antoine/dev/sc-zeth/build/src /home/user99/Documents/antoine/dev/sc-zeth/build/src/CMakeFiles/ExperimentalBuild.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/ExperimentalBuild.dir/depend

