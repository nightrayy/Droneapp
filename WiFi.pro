#-------------------------------------------------
#
# Project created by QtCreator 2017-03-13T08:05:24
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets printsupport

TARGET = WiFi
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    connecting.cpp \
    snifferwnd.cpp \
    snifferworker.cpp \
    qcustomplot.cpp \
    packetdetailswnd.cpp

HEADERS  += mainwindow.h \
    connecting.h \
    snifferwnd.h \
    snifferworker.h \
    qcustomplot.h \
    packetdetailswnd.h

FORMS    += mainwindow.ui \
    connecting.ui \
    snifferwnd.ui \
    packetdetailswnd.ui
