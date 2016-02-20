#define _CRT_SECURE_NO_WARNINGS 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include "sha1.h"

#if _WIN32
#define PRISize "Iu"
#include <conio.h>
#define fseek _fseeki64
#else
#define PRISize "zu"
#include <termios.h>
#endif

static const char* GM8E01_0_00_FILTERED_SHA1 =
"\x78\x3E\x35\xFC\x22\xB5\x6F\xA6\x1E\x98\xE0\x9C\x8B\x6E\x71\x4D\xC7\x89\xA4\x3B";

static inline uint32_t bswap32(uint32_t val)
{
#if __GNUC__
    return __builtin_bswap32(val);
#elif _WIN32
    return _byteswap_ulong(val);
#else
    val = (val & 0x0000FFFF) << 16 | (val & 0xFFFF0000) >> 16;
    val = (val & 0x00FF00FF) << 8 | (val & 0xFF00FF00) >> 8;
    return val;
#endif
}

static inline int16_t bswap16(int16_t val)
{
#if __GNUC__
    return __builtin_bswap16(val);
#elif _WIN32
    return _byteswap_ushort(val);
#else
    return (val = (val << 8) | ((val >> 8) & 0xFF));
#endif
}

static int GetTermChar()
{
    int ch;
#ifndef _WIN32
    struct termios tioOld, tioNew;
    tcgetattr(0, &tioOld);
    tioNew = tioOld;
    tioNew.c_lflag &= ~ICANON;
    tcsetattr(0, TCSANOW, &tioNew);
    ch = getchar();
    tcsetattr(0, TCSANOW, &tioOld);
#else
    ch = _getch();
#endif
    return ch;
}

struct RSFEntry
{
    const char* filename;
    uint32_t startSample;
    uint32_t endSample;
    bool edited;
};

static void PrintList(const struct RSFEntry entries[4])
{
    for (int i=0 ; i<4 ; ++i)
    {
        const struct RSFEntry* entry = &entries[i];
        printf("%d: %s [%d, %d]", i+1, entry->filename, entry->startSample, entry->endSample);
        if (entry->edited)
            printf("*");
        printf("\n");
    }
    printf("Type a number [1-4] to change, or 's' to save, or 'q' to cancel: ");
    fflush(stdout);
}

static void ScanSamples(struct RSFEntry* entry, bool hasStart)
{
    int start = 0;
    int end = 0;
    if (hasStart)
    {
        printf("%s start: ", entry->filename);
        fflush(stdout);
        if (scanf("%i", &start) != 1)
        {
            printf("error inputting start sample\n");
            return;
        }
    }
    printf("%s end: ", entry->filename);
    fflush(stdout);
    if (scanf("%i", &end) != 1)
    {
        printf("error inputting end sample\n");
        return;
    }
    if (start < 0 || end < 0)
    {
        printf("both values must be positive\n");
        return;
    }
    if (start > end)
    {
        printf("end must be greater than start\n");
        return;
    }
    entry->startSample = start & 0xfffffffe;
    entry->endSample = end & 0xfffffffe;
    entry->edited = true;
}

static void ReadSamples(struct RSFEntry* entry, FILE* fp,
                        size_t startHiOff, size_t startLoOff,
                        size_t endHiOff, size_t endLoOff)
{
    int16_t upper = 0;
    int16_t lower = 0;

    if (startHiOff || startLoOff)
    {
        fseek(fp, startHiOff, SEEK_SET);
        fread(&upper, 1, 2, fp);
        upper = bswap16(upper);
        fseek(fp, startLoOff, SEEK_SET);
        fread(&lower, 1, 2, fp);
        lower = bswap16(lower);
        entry->startSample = (((int32_t)upper) << 16) + ((int32_t)lower);
    }
    else
        entry->startSample = 0;

    if (endHiOff || endLoOff)
    {
        fseek(fp, endHiOff, SEEK_SET);
        fread(&upper, 1, 2, fp);
        upper = bswap16(upper);
        fseek(fp, endLoOff, SEEK_SET);
        fread(&lower, 1, 2, fp);
        lower = bswap16(lower);
        entry->endSample = (((int32_t)upper) << 16) + ((int32_t)lower);
    }
    else
        entry->endSample = 0;
}

static void WriteSamples(const struct RSFEntry* entry, FILE* fp,
                         size_t startHiOff, size_t startLoOff,
                         size_t endHiOff, size_t endLoOff)
{
    int16_t upper;
    int16_t lower;

    if (startHiOff || startLoOff)
    {
        upper = entry->startSample >> 16;
        lower = entry->startSample & 0xffff;
        if (lower < 0)
            upper += 1;
        upper = bswap16(upper);
        fseek(fp, startHiOff, SEEK_SET);
        fwrite(&upper, 1, 2, fp);
        lower = bswap16(lower);
        fseek(fp, startLoOff, SEEK_SET);
        fwrite(&lower, 1, 2, fp);
    }

    if (endHiOff || endLoOff)
    {
        upper = entry->endSample >> 16;
        lower = entry->endSample & 0xffff;
        if (lower < 0)
            upper += 1;
        upper = bswap16(upper);
        fseek(fp, endHiOff, SEEK_SET);
        fwrite(&upper, 1, 2, fp);
        lower = bswap16(lower);
        fseek(fp, endLoOff, SEEK_SET);
        fwrite(&lower, 1, 2, fp);
    }
}

static const size_t DynamicRegions[] =
{
    0x19f32,
    0x19f42,
    0x19f36,
    0x19f46,
    0x19fa6,
    0x19fb6,
    0x19faa,
    0x19fba,
    0x22b32,
    0x22b42,
    0x24046,
    0x24056,
    0x2404a,
    0x2405a
};

static void ZeroDynamicRegions(char buf[8192], size_t start)
{
    size_t end = start + 8192;
    for (int i=0 ; i<14 ; ++i)
    {
        size_t region = DynamicRegions[i];
        if (region >= start && region < end)
        {
            buf[region-start] = '\0';
            buf[region-start+1] = '\0';
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: RSFLoopPatcher <dol-in> [-f]\n");
        return 1;
    }
    bool force = false;
    if (argc >= 3 && argv[2][0] == '-' && argv[2][1] == 'f')
        force = true;

    /* Validate image */
    FILE* fp = fopen(argv[1], "rb");
    if (!fp)
    {
        fprintf(stderr, "Unable to open %s for reading\n", argv[1]);
        return 1;
    }

    if (!force)
    {
        printf("Validating '%s'\n", argv[1]);
        fflush(stdout);
        size_t totalBytes = 0;
        size_t rdBytes;
        char buf[8192];
        sha1nfo s;
        sha1_init(&s);
        while ((rdBytes = fread(buf, 1, 8192, fp)))
        {
            ZeroDynamicRegions(buf, totalBytes);
            sha1_write(&s, buf, rdBytes);
            totalBytes += rdBytes;
            printf(" %" PRISize " bytes\r", totalBytes);
            fflush(stdout);
        }
        printf("\n\n");
        fflush(stdout);

        uint8_t* fileHash = sha1_result(&s);
#if 0
        for (int i=0 ; i<20 ; ++i)
            printf("%02X", fileHash[i]);
        fflush(stdout);
#endif
        if (memcmp(GM8E01_0_00_FILTERED_SHA1, fileHash, 20))
        {
            fprintf(stderr,
                    "This tool is only made to patch raw GM8E01-0-00 NTSC .dol files\n"
                    "%s did not pass the hash validation\n", argv[1]);
            fclose(fp);
            return 1;
        }
    }

    /* Load current sample offsets */
    struct RSFEntry entries[4] = {0};

    entries[0].filename = "frontend_1.rsf";
    ReadSamples(&entries[0], fp, 0x19f32, 0x19f42, 0x19f36, 0x19f46);

    entries[1].filename = "frontend_2.rsf";
    ReadSamples(&entries[1], fp, 0x19fa6, 0x19fb6, 0x19faa, 0x19fba);

    entries[2].filename = "ending3.rsf";
    ReadSamples(&entries[2], fp, 0, 0, 0x22b32, 0x22b42);

    entries[3].filename = "samusjak.rsf";
    ReadSamples(&entries[3], fp, 0x24046, 0x24056, 0x2404a, 0x2405a);

    fclose(fp);

    while (true)
    {
        PrintList(entries);
        int opt;
        do {opt = tolower(GetTermChar());} while (opt == '\n');
        printf("\n");
        fflush(stdout);
        if (opt >= '1' && opt <= '4')
            ScanSamples(&entries[opt-'1'], opt != '3');
        else if (opt == 's')
        {
            fp = fopen(argv[1], "r+b");
            if (!fp)
            {
                fprintf(stderr, "Unable to open %s for writing\n", argv[1]);
                return 1;
            }
            if (entries[0].edited)
                WriteSamples(&entries[0], fp, 0x19f32, 0x19f42, 0x19f36, 0x19f46);
            if (entries[1].edited)
                WriteSamples(&entries[1], fp, 0x19fa6, 0x19fb6, 0x19faa, 0x19fba);
            if (entries[2].edited)
                WriteSamples(&entries[2], fp, 0, 0, 0x22b32, 0x22b42);
            if (entries[3].edited)
                WriteSamples(&entries[3], fp, 0x24046, 0x24056, 0x2404a, 0x2405a);
            fclose(fp);
            printf("Saved!!\n");
            return 0;
        }
        else if (opt == 'q')
            return 0;
        printf("\n");
    }

    return 0;
}
