# -------------------------------------------------
# Project configuration
# -------------------------------------------------

QT += widgets        # We use the Widgets module

# C++17 configuration
CONFIG += c++17
QMAKE_CXXFLAGS += -std=c++17

# Name of the target
TARGET = MyEncryptionApp
TEMPLATE = app

# Source files
SOURCES += \
    advancedencryption.cpp \
    main.cpp \
    mainwindow.cpp

# Header files
HEADERS += \
    advancedencryption.h \
    mainwindow.h

# UI files
FORMS += \
    mainwindow.ui
