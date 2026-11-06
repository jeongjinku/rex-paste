#import <AppKit/AppKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <stdlib.h>
#include <string.h>
extern int image_supported(const unsigned char *, size_t);
#define IMAGE_SOURCE_LIMIT (256 * 1024 * 1024)

// The caller frees the returned buffer. Tests use only a separate pasteboard.
// Returns 0 text, 1 image bytes, 2 regular file path (NUL-terminated), -1 error.
int clipboard_read(const char *board, unsigned char **out, size_t *len) {
    @autoreleasepool {
        NSPasteboard *pb = board ? [NSPasteboard pasteboardWithName:@(board)] : NSPasteboard.generalPasteboard;
        // Finder's TIFF/PNG may be the file icon, so read the actual file first.
        NSArray<NSURL *> *urls = [pb readObjectsForClasses:@[NSURL.class]
            options:@{NSPasteboardURLReadingFileURLsOnlyKey: @YES}];
        NSData *data = nil;
        if (urls.count) {
            NSURL *url = urls.firstObject;
            NSNumber *regular = nil, *size = nil;
            UTType *type = nil;
            if (![url getResourceValue:&regular forKey:NSURLIsRegularFileKey error:NULL] || !regular.boolValue) return -1;
            [url getResourceValue:&size forKey:NSURLFileSizeKey error:NULL];
            [url getResourceValue:&type forKey:NSURLContentTypeKey error:NULL];
            // Only image types are read to check decodability; anything else returns the original file path.
            if ([type conformsToType:UTTypeImage] && size.unsignedLongLongValue <= IMAGE_SOURCE_LIMIT) {
                NSFileHandle *file = [NSFileHandle fileHandleForReadingFromURL:url error:NULL];
                if (!file) return -1;
                data = [file readDataUpToLength:IMAGE_SOURCE_LIMIT + 1 error:NULL];
                [file closeAndReturnError:NULL];
                const unsigned char *bytes = data.bytes;
                BOOL png = data.length >= 8 && !memcmp(bytes, "\x89PNG\r\n\x1a\n", 8);
                BOOL webp = data.length >= 12 && !memcmp(bytes, "RIFF", 4) && !memcmp(bytes + 8, "WEBP", 4);
                if (!data.length || data.length > IMAGE_SOURCE_LIMIT || (!png && !webp && !image_supported(bytes, data.length))) data = nil;
            }
            if (!data) {
                *out = (unsigned char *)strdup(url.fileSystemRepresentation);
                if (!*out) return -1;
                *len = strlen((char *)*out);
                return 2;
            }
        } else {
            data = [pb dataForType:NSPasteboardTypePNG];
        }
        if (!data) {
            NSData *tiff = [pb dataForType:NSPasteboardTypeTIFF];
            if (tiff) {
                data = tiff;
                if (!image_supported(data.bytes, data.length)) return -1;
            }
        }
        int kind = data ? 1 : 0;
        if (!data) data = [([pb stringForType:NSPasteboardTypeString] ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
        if (data.length > (kind ? IMAGE_SOURCE_LIMIT : 4 * 1024 * 1024)) return -1;
        *len = data.length;
        *out = malloc(*len ? *len : 1);
        if (!*out) return -1;
        memcpy(*out, data.bytes, *len);
        return kind;
    }
}
