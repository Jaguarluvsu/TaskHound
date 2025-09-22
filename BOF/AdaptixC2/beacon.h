/*
 * beacon.h - AdaptixC2 BOF API declarations
 * 
 * Contains function prototypes for approved Adaptix BOF APIs
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

// Callback types for BeaconOutput
#define CALLBACK_OUTPUT     0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR      0x0d

// Data parser structure (opaque)
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

// Format structure (opaque)
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} formatp;

// Data Parser API
DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int BeaconDataInt(datap* parser);
DECLSPEC_IMPORT int BeaconDataLength(datap* parser);
DECLSPEC_IMPORT void BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT short BeaconDataShort(datap* parser);

// Output API
DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int len);

// Format API
DECLSPEC_IMPORT void BeaconFormatAlloc(formatp* obj, int maxsz);
DECLSPEC_IMPORT void BeaconFormatAppend(formatp* obj, char* data, int len);
DECLSPEC_IMPORT void BeaconFormatFree(formatp* obj);
DECLSPEC_IMPORT void BeaconFormatInt(formatp* obj, int val);
DECLSPEC_IMPORT void BeaconFormatPrintf(formatp* obj, char* fmt, ...);
DECLSPEC_IMPORT void BeaconFormatReset(formatp* obj);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp* obj, int* size);

// Internal APIs
DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken();
DECLSPEC_IMPORT BOOL BeaconIsAdmin();
DECLSPEC_IMPORT BOOL toWideChar(char* src, wchar_t* dst, int max);

DECLSPEC_IMPORT BOOL BeaconAddValue(const char* key, void* ptr);
DECLSPEC_IMPORT void* BeaconGetValue(const char* key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char* key);

#endif // BEACON_H