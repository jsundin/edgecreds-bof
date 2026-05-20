#pragma once

#include <windows.h>

DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char * data, int len);

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);

DECLSPEC_IMPORT BOOL toWideChar(char * src, wchar_t * dst, int max);
