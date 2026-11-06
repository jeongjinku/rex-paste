// Clipboard and codec tests on a private named pasteboard; the system clipboard is never touched.
// Run with: sh test/clipboard_test.sh
#import <AppKit/AppKit.h>
#include <assert.h>
#include "../src/mac.m"
#include <png.h>
#include <webp/encode.h>
#include <webp/decode.h>
static int png_rows, webp_encodes;
static void tracked_png_row(png_structp p, png_const_bytep row) { png_rows++; png_write_row(p, row); }
static int tracked_webp(const WebPConfig *c, WebPPicture *p) { webp_encodes++; return WebPEncode(c, p); }
#define png_write_row tracked_png_row
#define WebPEncode tracked_webp
#include "../src/codec.c"
#undef png_write_row
#undef WebPEncode

static void prepared(NSData *input, int width, int height) {
    unsigned char *out = NULL; size_t size = 0;
    png_rows = webp_encodes = 0;
    assert(encode_image(input.bytes, input.length, &out, &size, 0));
    assert(png_rows == 0 && webp_encodes == 1);
    int w, h; unsigned char *pixels = WebPDecodeRGBA(out, size, &w, &h);
    assert(pixels && w == width && h == height);
    CGImageSourceRef source = image_source(input.bytes, input.length);
    CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    assert(image);
    CGColorSpaceRef space = CGImageGetColorSpace(image);
    if (space && CGColorSpaceGetModel(space) == kCGColorSpaceModelRGB) {
        CFDataRef expected = CGColorSpaceCopyICCData(space);
        if (expected) {
            WebPData bytes = {out, size}, profile = {0};
            WebPMux *mux = WebPMuxCreate(&bytes, 0);
            assert(WebPMuxGetChunk(mux, "ICCP", &profile) == WEBP_MUX_OK);
            assert(profile.size == (size_t)CFDataGetLength(expected));
            assert(!memcmp(profile.bytes, CFDataGetBytePtr(expected), profile.size));
            WebPMuxDelete(mux); CFRelease(expected);
        }
    }
    CGImageRelease(image); CFRelease(source);
    WebPFree(pixels); free(out);
}

static void installed(const char *binary, NSURL *file, int width, int height) {
    NSTask *task = [NSTask new];
    task.executableURL = [NSURL fileURLWithPath:@(binary)];
    task.arguments = @[@"prepare", file.path];
    NSPipe *pipe = [NSPipe pipe]; task.standardOutput = pipe;
    assert([task launchAndReturnError:NULL]);
    NSData *result = [pipe.fileHandleForReading readDataToEndOfFile];
    [task waitUntilExit]; assert(task.terminationStatus == 0);
    NSDictionary *info = [NSJSONSerialization JSONObjectWithData:result options:0 error:NULL];
    NSData *webp = [NSData dataWithContentsOfFile:info[@"path"]];
    int w, h; assert(WebPGetInfo(webp.bytes, webp.length, &w, &h));
    assert(w == width && h == height);
}

static void seed(NSPasteboard *pb, NSURL *url, NSData *png, NSData *tiff) {
    [pb clearContents];
    NSPasteboardItem *item = [NSPasteboardItem new];
    if (url) assert([item setString:url.absoluteString forType:NSPasteboardTypeFileURL]);
    if (png) assert([item setData:png forType:NSPasteboardTypePNG]);
    if (tiff) assert([item setData:tiff forType:NSPasteboardTypeTIFF]);
    assert([pb writeObjects:@[item]]);
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        NSString *name = [@"rex-paste-file-test-" stringByAppendingString:NSUUID.UUID.UUIDString];
        NSPasteboard *pb = [NSPasteboard pasteboardWithName:name];
        NSURL *dir = [NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:name]];
        assert([NSFileManager.defaultManager createDirectoryAtURL:dir withIntermediateDirectories:NO attributes:nil error:NULL]);
        NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
            pixelsWide:3 pixelsHigh:2 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES
            isPlanar:NO colorSpaceName:NSDeviceRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
        memset(bitmap.bitmapData, 255, bitmap.bytesPerRow * bitmap.pixelsHigh);
        NSData *original = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        memset(bitmap.bitmapData, 0, bitmap.bytesPerRow * bitmap.pixelsHigh);
        NSData *icon = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        NSData *tiff = bitmap.TIFFRepresentation;
        NSURL *file = [dir URLByAppendingPathComponent:@"résumé image.png"];
        assert([original writeToURL:file atomically:YES]);
        unsigned char *out = NULL; size_t size = 0;
        seed(pb, file, icon, tiff);
        assert(clipboard_read(name.UTF8String, &out, &size) == 1);
        assert(size == original.length && !memcmp(out, original.bytes, size)); free(out);

        NSURL *jpeg = [dir URLByAppendingPathComponent:@"image.jpg"];
        NSData *jpg = [bitmap representationUsingType:NSBitmapImageFileTypeJPEG properties:@{}];
        assert(jpg && [jpg writeToURL:jpeg atomically:YES]);
        seed(pb, jpeg, original, tiff);
        assert(clipboard_read(name.UTF8String, &out, &size) == 1);
        assert(size == jpg.length && !memcmp(out, jpg.bytes, size));
        prepared([NSData dataWithBytes:out length:size], 3, 2); free(out);
        if (argc == 2) installed(argv[1], jpeg, 3, 2);

        // Generate a real HEIC image in a HEIF container and verify the file URL path end to end.
        NSMutableData *heif = [NSMutableData data];
        CGImageDestinationRef destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)heif,
            CFSTR("public.heic"), 1, NULL);
        assert(destination);
        CGImageDestinationAddImage(destination, bitmap.CGImage, NULL);
        assert(CGImageDestinationFinalize(destination)); CFRelease(destination);
        for (NSString *ext in @[@"heic", @"heif"]) {
            NSURL *file_url = [dir URLByAppendingPathComponent:[@"image." stringByAppendingString:ext]];
            assert([heif writeToURL:file_url atomically:YES]);
            seed(pb, file_url, original, tiff);
            assert(clipboard_read(name.UTF8String, &out, &size) == 1);
            assert(size == heif.length && !memcmp(out, heif.bytes, size));
            prepared([NSData dataWithBytes:out length:size], 3, 2); free(out);
            if (argc == 2) installed(argv[1], file_url, 3, 2);
        }

        NSMutableData *rotated = [NSMutableData data];
        destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)rotated, CFSTR("public.jpeg"), 1, NULL);
        assert(destination);
        CGImageDestinationAddImage(destination, bitmap.CGImage,
            (__bridge CFDictionaryRef)@{(__bridge NSString *)kCGImagePropertyOrientation: @6});
        assert(CGImageDestinationFinalize(destination)); CFRelease(destination);
        prepared(rotated, 2, 3);

        NSBitmapImageRep *rgba = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
            pixelsWide:4 pixelsHigh:2 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES
            isPlanar:NO colorSpaceName:NSCalibratedRGBColorSpace bitmapFormat:NSBitmapFormatAlphaNonpremultiplied
            bytesPerRow:0 bitsPerPixel:0];
        for (int y=0;y<2;y++) for (int x=0;x<4;x++) {
            unsigned char *p = rgba.bitmapData+y*rgba.bytesPerRow+x*4;
            p[0]=y ? 20 : 200; p[1]=40; p[2]=y ? 180 : 10; p[3]=(unsigned char[]){0,1,128,255}[x];
        }
        NSData *alpha = rgba.TIFFRepresentation;
        prepared(alpha, 4, 2);
        assert(encode_image(alpha.bytes, alpha.length, &out, &size, 0));
        int aw, ah; unsigned char *ap = WebPDecodeRGBA(out, size, &aw, &ah);
        assert(ap && aw==4 && ah==2);
        for (int y=0;y<2;y++) for (int x=0;x<4;x++) {
            unsigned char *expected = rgba.bitmapData+y*rgba.bytesPerRow+x*4;
            unsigned char *actual = ap+(y*4+x)*4;
            assert(!memcmp(expected, actual, 4));
        }
        WebPFree(ap); free(out);
        const unsigned order[8][8] = {
            {0,1,2,3,4,5,6,7}, {3,2,1,0,7,6,5,4}, {7,6,5,4,3,2,1,0}, {4,5,6,7,0,1,2,3},
            {0,4,1,5,2,6,3,7}, {4,0,5,1,6,2,7,3}, {7,3,6,2,5,1,4,0}, {3,7,2,6,1,5,0,4}
        };
        for (int orientation=1;orientation<=8;orientation++) {
            NSMutableData *oriented = [NSMutableData data];
            destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)oriented, CFSTR("public.tiff"), 1, NULL);
            assert(destination);
            CGImageDestinationAddImage(destination, rgba.CGImage,
                (__bridge CFDictionaryRef)@{(__bridge NSString *)kCGImagePropertyOrientation: @(orientation)});
            assert(CGImageDestinationFinalize(destination)); CFRelease(destination);
            assert(encode_image(oriented.bytes, oriented.length, &out, &size, 0));
            ap = WebPDecodeRGBA(out, size, &aw, &ah);
            assert(ap && aw==(orientation>=5?2:4) && ah==(orientation>=5?4:2));
            for (int i=0;i<8;i++) {
                unsigned source=order[orientation-1][i];
                assert(!memcmp(ap+i*4, rgba.bitmapData+(source/4)*rgba.bytesPerRow+(source%4)*4, 4));
            }
            WebPFree(ap); free(out);
        }

        // PNG with an EXIF orientation: libpng would ignore it, so the pixels must come out rotated.
        NSMutableData *oriented_png = [NSMutableData data];
        destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)oriented_png, CFSTR("public.png"), 1, NULL);
        assert(destination);
        CGImageDestinationAddImage(destination, rgba.CGImage,
            (__bridge CFDictionaryRef)@{(__bridge NSString *)kCGImagePropertyOrientation: @6});
        assert(CGImageDestinationFinalize(destination)); CFRelease(destination);
        assert(encode_image(oriented_png.bytes, oriented_png.length, &out, &size, 0));
        ap = WebPDecodeRGBA(out, size, &aw, &ah);
        assert(ap && aw == 2 && ah == 4);
        WebPFree(ap); free(out);

        NSURL *large = [dir URLByAppendingPathComponent:@"large.png"];
        assert([NSData.data writeToURL:large atomically:YES]);
        NSFileHandle *large_file = [NSFileHandle fileHandleForWritingToURL:large error:NULL];
        assert([large_file truncateAtOffset:IMAGE_SOURCE_LIMIT+1 error:NULL]);
        assert([large_file closeAndReturnError:NULL]);

        NSBitmapImageRep *large_bitmap = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
            pixelsWide:2048 pixelsHigh:1024 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES
            isPlanar:NO colorSpaceName:NSDeviceRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
        memset(large_bitmap.bitmapData, 255, large_bitmap.bytesPerRow*large_bitmap.pixelsHigh);
        NSData *large_tiff = large_bitmap.TIFFRepresentation;
        assert(large_tiff.length > 4*1024*1024);
        seed(pb, nil, nil, large_tiff);
        assert(clipboard_read(name.UTF8String, &out, &size) == 1);
        assert(size == large_tiff.length && !memcmp(out, large_tiff.bytes, size)); free(out);
        prepared(large_tiff, 2000, 1000);
        // setup{max_dimension=...} changes the bound; resize=false sets it to 0 and keeps the size.
        rex_max_dimension = 500; prepared(large_tiff, 500, 250);
        rex_max_dimension = 0; prepared(large_tiff, 2048, 1024);
        // compress=false: images over the bound are re-encoded in their own format.
        for (NSString *uti in @[@"public.jpeg", @"public.heic", @"public.tiff"]) {
            NSMutableData *source = [NSMutableData data];
            destination = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)source, (__bridge CFStringRef)uti, 1, NULL);
            assert(destination);
            CGImageDestinationAddImage(destination, large_bitmap.CGImage, NULL);
            assert(CGImageDestinationFinalize(destination)); CFRelease(destination);
            unsigned sw, sh; assert(image_dimensions(source.bytes, source.length, &sw, &sh) && sw == 2048 && sh == 1024);
            rex_max_dimension = 500;
            assert(encode_same_format(source.bytes, source.length, &out, &size));
            CGImageSourceRef result = image_source(out, size);
            assert(result && [(__bridge NSString *)CGImageSourceGetType(result) isEqualToString:uti]);
            unsigned rw, rh; assert(image_dimensions(out, size, &rw, &rh) && rw == 500 && rh == 250);
            CFRelease(result); free(out);
        }
        rex_max_dimension = 2000;
        assert(encode_image(large_tiff.bytes, large_tiff.length, &out, &size, 0));
        assert(size < 4*1024*1024); free(out);
        NSURL *large_tiff_url = [dir URLByAppendingPathComponent:@"large.tiff"];
        assert([large_tiff writeToURL:large_tiff_url atomically:YES]);
        if (argc == 2) installed(argv[1], large_tiff_url, 2000, 1000);

        NSURL *text = [dir URLByAppendingPathComponent:@"notes.txt"];
        assert([@"not an image" writeToURL:text atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
        // Regular files and undecodable large images return the original path, not the icon.
        for (NSURL *url in @[text, large]) {
            seed(pb, url, icon, tiff);
            assert(clipboard_read(name.UTF8String, &out, &size) == 2);
            assert(size == strlen(url.fileSystemRepresentation) && !memcmp(out, url.fileSystemRepresentation, size + 1)); free(out);
        }
        for (NSURL *url in @[dir, [dir URLByAppendingPathComponent:@"missing.png"]]) {
            seed(pb, url, icon, tiff);
            assert(clipboard_read(name.UTF8String, &out, &size) == -1);
        }
        seed(pb, nil, original, tiff);
        assert(clipboard_read(name.UTF8String, &out, &size) == 1);
        assert(size == original.length && !memcmp(out, original.bytes, size)); free(out);
        seed(pb, nil, nil, tiff);
        assert(clipboard_read(name.UTF8String, &out, &size) == 1);
        assert(size == tiff.length && !memcmp(out, tiff.bytes, size));
        prepared([NSData dataWithBytes:out length:size], 3, 2); free(out);
        [pb clearContents];
        NSData *utf8 = [@"café text \n" dataUsingEncoding:NSUTF8StringEncoding];
        assert([pb setString:@"café text \n" forType:NSPasteboardTypeString]);
        assert(clipboard_read(name.UTF8String, &out, &size) == 0);
        assert(size == utf8.length && !memcmp(out, utf8.bytes, size)); free(out);
        assert([[NSData dataWithContentsOfURL:file] isEqualToData:original]);
        [pb releaseGlobally];
        assert([NSFileManager.defaultManager removeItemAtURL:dir error:NULL]);
        puts("Finder URL priority, JPEG/HEIF/TIFF direct WebP (zero PNG writes), raw file paths, resize bound, same-format resize, PNG and text: passed");
    }
}
