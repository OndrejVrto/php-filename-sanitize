<?php

declare(strict_types=1);

namespace OndrejVrto\FilenameSanitize;

use Exception;

final class FilenameSanitize {
    public function __invoke(string $filename): string {
        // Replace special characters
        $filename = preg_replace([
            '/[<>:"\/\\\|?*]/',         // file system reserved https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
            '/[\x00-\x1F]/',            // control characters http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            '/[\x7F\xA0\xAD]/',         // non-printing characters DEL, NO-BREAK SPACE, SOFT HYPHEN
            '/[#\[\]@!$&\'()+,;=]/',    // URI reserved https://www.rfc-editor.org/rfc/rfc3986#section-2.2
            '/[{}^\~`]/',               // URL unsafe characters https://www.ietf.org/rfc/rfc1738.txt
            '/ +/',                     // reduce consecutive characters "file   name.zip" becomes "file-name.zip"
            '/_+/',                     // reduce consecutive characters "file___name.zip" becomes "file-name.zip"
            '/-+/',                     // reduce consecutive characters "file---name.zip" becomes "file-name.zip"
        ], '-', self::checkEmptyString($filename));

        // reduce consecutive characters and replace with dot
        $filename = preg_replace([
            '/-*\.-*/',     // "file--.--.-.--name.zip" becomes "file.name.zip"
            '/\.{2,}/',     // "file...name..zip" becomes "file.name.zip"
        ], '.', self::checkEmptyString($filename));

        // clean start and end string with multiple trim pipe
        $filename = trim(rtrim(rtrim(rtrim(self::checkEmptyString($filename)), '.-')), '-');

        $encoding = mb_detect_encoding(self::checkEmptyString($filename)) ?: 'ASCII';

        // lowercase for windows/unix interoperability https://en.wikipedia.org/wiki/Filename
        $filename = mb_strtolower($filename, $encoding);

        // cut filename length to 255 bytes http://serverfault.com/a/9548/44086
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        $filename = mb_strcut(
            string: pathinfo($filename, PATHINFO_FILENAME),
            start: 0,
            length: 255 - (empty($ext) ? 0 : mb_strlen($ext) + 1),
            encoding: $encoding
        );

        return empty($ext) ? $filename : "{$filename}.{$ext}";
    }

    private static function checkEmptyString(?string $str): string {
        if (empty($str)) {
            throw new Exception("Incorect filename. A string of zero length is returned.", 5);
        }

        return $str;
    }
}
