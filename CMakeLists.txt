# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(ZeekPluginClusterBackendNATS)

# Establish version numbers in config.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

# Process any package-specific customizations
include(plugin.cmake OPTIONAL)

include(ZeekPlugin)

zeek_add_plugin(
    Zeek
    Cluster_Backend_NATS
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBNATS_INCLUDE_DIRS}
    DEPENDENCIES
    ${LIBNATS_LIBRARIES}
    SOURCES
    src/NATS.cc
    src/Plugin.cc
    DIST_FILES
    README.md
    CHANGES
    COPYING
    VERSION
)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
