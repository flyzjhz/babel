# Weiwei Jia <harryxiyou@gmail.com>.
# Time & Place: 2011, 3, 26, @ linux lab in xiyou.

# This *ON* can let cmake procedure output into console.
# _So_that we can debug it.
SET(CMAKE_VERBOSE_MAKEFILE ON)
PROJECT(Babel)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(WORK_HOME $ENV{PWD}/..)
MESSAGE(STATUS "Current Work Dir :" ${WORK_HOME})
SET(LIBPCAP_HOME ${WORK_HOME}/3part/libpcap)
MESSAGE(STATUS "libpcap Work Dir :" ${LIBPCAP_HOME})

INCLUDE_DIRECTORIES(
		${LIBPCAP}/include
        /usr/include/
		include
		.)
# Use SRCS to save all the sources.
# If it has subdirectory, use following commands for adding.

#---------------------- Make all ------------------------------#
ADD_CUSTOM_TARGET(all)

#----------------------- Make tools ---------------------------#
ADD_CUSTOM_TARGET(tools)
IF(CMAKE_SIZEOF_VOID_P EQUAL 4)
LINK_DIRECTORIES(
#		/usr/lib/x86_64-linux-gnu
        ${LIBPCAP_HOME}/lib)
ELSEIF(CMAKE_SIZEOF_VOID_P EQUAL 8)
LINK_DIRECTORIES(
#		/usr/lib/x86_64-linux-gnu
        ${LIBPCAP_HOME}/lib)
ENDIF(CMAKE_SIZEOF_VOID_P EQUAL 4)

SET(TOOLLIBS pcap)

SET(EXECUTABLE_OUTPUT_PATH output/bin)
SET(TOOLSRCS ../src/md5.c
			 ../src/mentohust.c
			 ../src/mycheck.c
			 ../src/myconfig.c
			 ../src/myfunc.c
			 ../src/myini.c
			 ../src/mystate.c)
ADD_EXECUTABLE(babel ${TOOLSRCS})
TARGET_LINK_LIBRARIES(babel ${TOOLLIBS})
SET_TARGET_PROPERTIES(babel PROPERTIES COMPILE_FLAGS "-g -Wstrict-prototypes")

ADD_DEPENDENCIES(tools babel)
ADD_DEPENDENCIES(all tools)
#--------------------- Make all end -----------------------------#
