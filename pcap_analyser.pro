QT += core
QT -= gui

TARGET = pcap_analyser
CONFIG += console
CONFIG -= app_bundle
LIBS += -lpcap

TEMPLATE = app

SOURCES += main.cpp

