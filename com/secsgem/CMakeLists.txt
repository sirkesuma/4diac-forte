# *******************************************************************************
# *******************************************************************************
# Copyright (c) 2025 Edo Kesuma, github.com/sirkesuma This program and the
# accompanying materials are made available under the terms of the Eclipse
# Public License 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0.
#
# SPDX-License-Identifier: EPL-2.0
#
# Contributors: Edo Kesuma
# *******************************************************************************/
# *******************************************************************************/
# ############################################################################
# SECS/GEM Com Layer (currently implements an SECS/GEM active mode (client) over HSMS)
# ############################################################################
option(FORTE_COM_SECSGEM "Enable a SECS/GEM Com Layer" OFF)
if (NOT FORTE_COM_SECSGEM)
    return()
endif ()

add_library(forte-com-secsgem
	secsgemtypes.h
        secsgemlayer.cpp
        secsgemlayer.h
        secsgemparser.h
        secsgemparser.cpp
        secsgemhandler.h
        secsgemhandler.cpp
)
# target_include_directories(forte-com-secsgem PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(forte-com-secsgem PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(forte-com-secsgem PUBLIC forte-core)
target_link_libraries(forte PUBLIC $<IF:$<BOOL:${BUILD_SHARED_LIBS}>,forte-com-secsgem,$<LINK_LIBRARY:WHOLE_ARCHIVE,forte-com-secsgem>>)

install(TARGETS forte-com-secsgem EXPORT forte-export FILE_SET HEADERS)
