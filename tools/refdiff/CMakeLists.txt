# refdiff is pure Python; this only registers its unit tests with ctest.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_test(NAME refdiff_unit
    COMMAND ${Python3_EXECUTABLE} -m unittest discover
            -s ${CMAKE_CURRENT_SOURCE_DIR}/tests -t ${CMAKE_CURRENT_SOURCE_DIR}/tests)
else()
  message(STATUS "Python3 not found: skipping refdiff_unit test")
endif()
