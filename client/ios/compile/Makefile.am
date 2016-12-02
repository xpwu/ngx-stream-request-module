ACLOCAL_AMFLAGS=-I m4
##AUTOMAKE_OPTIONS = subdir-objects
AUTOMAKE_OPTIONS = --warnings=none

noinst_LIBRARIES = libclient_armv7s.a libclient_armv7.a libclient_arm64.a \
										libclient_i386.a libclient_x64.a 
#noinst_PROGRAMS = stmclient


INCLUDES = -I ${top_srcdir}/..

MODE=release
MODE_FLAGS=-DNDEBUG
CXXFLAGS=-O2
CFLAGS=-O2

# ##---ios var
IOS_MIN_SDK=7.0
##IPHONEOS_SYSROOT=""
##IPHONESIMULATOR_SYSROOT=""
if MACOS
  XCODEDIR=/Applications/Xcode.app/Contents/Developer
  IPHONEOS_SYSROOT=${XCODEDIR}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
  IPHONESIMULATOR_SYSROOT=${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk
else
endif

COM_CFLAGS=$(MODE_FLAGS) -pipe -fPIC -fobjc-arc -miphoneos-version-min=$(IOS_MIN_SDK)# -fcxx-exceptions
IOS_CFLAGS=-isysroot $(IPHONEOS_SYSROOT) $(COM_CFLAGS) -fembed-bitcode
SIM_CFLAGS=-isysroot ${IPHONESIMULATOR_SYSROOT} $(COM_CFLAGS)
IOS_OBJCFLAGS=${IOS_CFLAGS}
SIM_OBJCFLAGS=${SIM_CFLAGS}
COM_CXXFLAGS=-std=c++11  -stdlib=libc++
IOS_CXXFLAGS=${IOS_CFLAGS} $(COM_CXXFLAGS)
SIM_CXXFLAGS=${SIM_CFLAGS} $(COM_CXXFLAGS)
IOS_OBJCXXFLAGS=${IOS_CXXFLAGS}
SIM_OBJCXXFLAGS=${SIM_CXXFLAGS}


# ##---ios var end


ios_common_SOURCES= ${top_srcdir}/../STMClient.m \
										${top_srcdir}/../STMDefaultContentProtocol.m \
										${top_srcdir}/../STMNet.mm \
										${top_srcdir}/../STMResponse.m

libclient_armv7s_a_SOURCES = $(ios_common_SOURCES)
libclient_armv7s_a_CXXFLAGS=$(IOS_CXXFLAGS) -arch armv7s 
libclient_armv7s_a_OBJCXXFLAGS=$(IOS_OBJCXXFLAGS) -arch armv7s 
libclient_armv7s_a_OBJCFLAGS=$(IOS_OBJCFLAGS) -arch armv7s 

libclient_armv7_a_SOURCES = $(ios_common_SOURCES)
libclient_armv7_a_CXXFLAGS=$(IOS_CXXFLAGS) -arch armv7
libclient_armv7_a_OBJCXXFLAGS=$(IOS_OBJCXXFLAGS) -arch armv7
libclient_armv7_a_OBJCFLAGS=$(IOS_OBJCFLAGS) -arch armv7

libclient_arm64_a_SOURCES = $(ios_common_SOURCES)
libclient_arm64_a_CXXFLAGS=$(IOS_CXXFLAGS) -arch arm64
libclient_arm64_a_OBJCXXFLAGS=$(IOS_OBJCXXFLAGS) -arch arm64
libclient_arm64_a_OBJCFLAGS=$(IOS_OBJCFLAGS) -arch arm64

libclient_i386_a_SOURCES = $(ios_common_SOURCES)
libclient_i386_a_CXXFLAGS=$(SIM_CXXFLAGS) -arch i386
libclient_i386_a_OBJCXXFLAGS=$(SIM_OBJCXXFLAGS) -arch i386
libclient_i386_a_OBJCFLAGS=$(SIM_OBJCFLAGS) -arch i386

libclient_x64_a_SOURCES = $(ios_common_SOURCES)
libclient_x64_a_CXXFLAGS=$(SIM_CXXFLAGS) -arch x86_64
libclient_x64_a_OBJCXXFLAGS=$(SIM_OBJCXXFLAGS) -arch x86_64
libclient_x64_a_OBJCFLAGS=$(SIM_OBJCFLAGS) -arch x86_64

#stmclient_SOURCES = ${top_srcdir}/../ios-sdk/ios-sdk/main.m
#stmclient_OBJCFLAGS = $(MODE_FLAGS) -isysroot ${XCODEDIR}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk
#stmclient_LDFLAGS = -framework Foundation 
#stmclient_LDADD = ${top_srcdir}/../out/$(MODE)/libstmclient.a

all-local:libclient_armv7.a libclient_arm64.a libclient_i386.a libclient_x64.a libclient_armv7s.a # stmclient
	@if ! [ -d ${top_srcdir}/../out/$(MODE) ] ;then \
		mkdir -p ${top_srcdir}/../out/$(MODE); \
	fi
	lipo -create libclient_armv7.a libclient_arm64.a libclient_i386.a libclient_x64.a libclient_armv7s.a \
        -output	${top_srcdir}/../out/$(MODE)/libstmclient.a	
	@cp ${top_srcdir}/../STMClient.h ${top_srcdir}/../out/STMClient.h
#	@cp stmclient ${top_srcdir}/../out/$(MODE)/stmclient
	@echo "BUILD SUCCESS ---out/$(MODE)"


debug:
	$(MAKE) all CFLAGS="-g" CXXFLAGS="-g" MODE="debug" MODE_FLAGS="-DDEBUG"


