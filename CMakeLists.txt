cmake_minimum_required(VERSION 3.5)

project(libdomain-qt-test VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

include(FindLdap)

find_package(Ldap REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(Libverto REQUIRED IMPORTED_TARGET libverto)
pkg_check_modules(Glib REQUIRED IMPORTED_TARGET glib-2.0)
pkg_check_modules(Talloc REQUIRED IMPORTED_TARGET talloc)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(libdomain-qt-test
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET libdomain-qt-test APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(libdomain-qt-test SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(libdomain-qt-test
            ${PROJECT_SOURCES}
        )
    endif()
endif()

include_directories("/home/user/Develop/libdomain-local/src/")
target_link_directories(libdomain-qt-test PRIVATE "/home/user/Develop/libdomain-local/build/lib64/")

target_link_libraries(libdomain-qt-test PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(libdomain-qt-test PRIVATE PkgConfig::Libverto PkgConfig::Glib PkgConfig::Talloc)
target_link_libraries(libdomain-qt-test PRIVATE Ldap::Ldap)
target_link_libraries(libdomain-qt-test PRIVATE "/home/user/Develop/libdomain-local/build/lib64/libdomain.so")

set_target_properties(libdomain-qt-test PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

install(TARGETS libdomain-qt-test
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(libdomain-qt-test)
endif()
