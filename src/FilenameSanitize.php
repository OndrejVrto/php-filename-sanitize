<?php

declare(strict_types=1);

namespace OndrejVrto\FilenameSanitize;

use ValueError;

final class FilenameSanitize {
    private const SEPARATOR = '-';

    private readonly string $encoding;
    private readonly string $dirname;
    private readonly string $filename;
    private readonly string $extension;

    private ?string $prefix          = null;
    private ?string $surfix          = null;
    private ?string $newExtension    = null;
    private bool    $withDirectory   = false;
    private bool    $addOldExtToName = false;

    public static function of(string $file): self {
        return (new self($file));
    }

    public function __construct(string $file) {
        if (empty($file) || '.' === $file || '..' === $file) {
            throw new ValueError("Incorect filename.", 5);
        }

        $this->encoding = mb_detect_encoding($file) ?: 'ASCII';

        $path_parts = pathinfo($file);

        $this->dirname = '.' === $path_parts['dirname']
            ? ''
            : $this->sanitizeDirectory($path_parts['dirname']);

        $this->filename = $this->sanitizePartOfFilename($path_parts['filename']);

        $this->extension = array_key_exists('extension', $path_parts)
            ? $this->sanitizePartOfFilename($path_parts['extension'])
            : '';
    }


    /* -------------------------------------------------------------------------- */
    /*                              SETTINGS METHODS                              */
    /* -------------------------------------------------------------------------- */
    public function widthFilenamePrefix(string $prefix): self {
        $this->prefix = $this->sanitizePartOfFilename(
            $this->encodingString($prefix)
        );

        return $this;
    }

    public function widthFilenameSurfix(string $surfix): self {
        $this->surfix = $this->sanitizePartOfFilename(
            $this->encodingString($surfix)
        );

        return $this;
    }

    public function withNewExtension(string $extension): self {
        $this->newExtension = $this->sanitizePartOfFilename(
            $this->encodingString($extension)
        );

        return $this;
    }

    public function moveActualExtensionToFilename(): self {
        $this->addOldExtToName = true;

        return $this;
    }

    public function withDirectory(): self {
        $this->withDirectory = true;

        return $this;
    }

    /* -------------------------------------------------------------------------- */
    /*                                MAIN METHODS                                */
    /* -------------------------------------------------------------------------- */
    public function get(): string {
        // format:  /directory/sanitize-filenanme.ext
        return sprintf(
            '%s%s',
            $this->getDirName(),
            $this->getformatedFilename($this->cutFilenameLength())
        );
    }

    public function getWithBaseDirectory(string $baseDirectory): string {
        $tmp = $baseDirectory.DIRECTORY_SEPARATOR.$this->get();

        return preg_replace([
            '/\\\{2,}/',
            '/\/{2,}/',
            '/\/\\\/',
            '#\\\/.*#',
        ], DIRECTORY_SEPARATOR, $tmp);
    }


    /* -------------------------------------------------------------------------- */
    /*                           PRIVATE HELPERS METHODS                          */
    /* -------------------------------------------------------------------------- */
    private function encodingString(string $str): string {
        return mb_convert_encoding($str, $this->encoding) ?: $str;
    }

    private function sanitizePartOfFilename(string $filenamePart): string {
        if (empty($filenamePart)) {
            return '';
        }

        // Replace special characters
        $filenamePart = preg_replace([
            '/[<>:"\/\\\|?*]/',         // file system reserved https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
            '/[\x00-\x1F]/',            // control characters http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            '/[\x7F\xA0\xAD]/',         // non-printing characters DEL, NO-BREAK SPACE, SOFT HYPHEN
            '/[#\[\]@!$&\'()+,;=]/',    // URI reserved https://www.rfc-editor.org/rfc/rfc3986#section-2.2
            '/[{}^\~`]/',               // URL unsafe characters https://www.ietf.org/rfc/rfc1738.txt
            '/ +/',                     // reduce consecutive characters "file   name.zip" becomes "file-name.zip"
            '/_+/',                     // reduce consecutive characters "file___name.zip" becomes "file-name.zip"
            '/-+/',                     // reduce consecutive characters "file---name.zip" becomes "file-name.zip"
        ], self::SEPARATOR, $filenamePart);

        if (empty($filenamePart)) {
            return '';
        }

        // reduce consecutive characters and replace with dot
        $filenamePart = preg_replace([
            '/-*\.-*/',     // "file--.--.-.--name.zip" becomes "file.name.zip"
            '/\.{2,}/',     // "file...name..zip" becomes "file.name.zip"
        ], '.', $filenamePart);

        if (empty($filenamePart)) {
            return '';
        }

        // clean start and end string with multiple trim pipe
        return trim(rtrim(rtrim(rtrim($filenamePart), '.'.self::SEPARATOR)), self::SEPARATOR);
    }

    private function sanitizeDirectory(string $dir): string {
        $tmp = preg_split('/\/|\\\/', $dir);

        if ( ! $tmp) {
            return '';
        }

        $tmp = array_map(function (string $dirNode) {
            if ($dirNode === '.' || $dirNode === '..' || $dirNode === '~') {
                return $dirNode;
            }

            return $this->sanitizePartOfFilename($dirNode);
        }, $tmp);

        $tmp = array_filter($tmp, fn (string $dirNode) => ! empty($dirNode));

        if (preg_match("/^(\/|\\\).*/", $dir)) {
            array_unshift($tmp, null);
        }

        return implode(DIRECTORY_SEPARATOR, $tmp);
    }

    private function getformatedFilename(string $filename): string {
        // Filename format:  prefix-filename-surfix-oldExtension.newExtension
        $tmp = sprintf(
            '%s%s%s%s%s',
            null === $this->prefix ? '' : $this->prefix.self::SEPARATOR,
            $filename,
            null === $this->surfix ? '' : self::SEPARATOR.$this->surfix,
            $this->addOldExtToName && ! empty($this->extension) ? self::SEPARATOR.$this->extension : '',
            $this->getExtension(),
        );

        // lowercase for windows/unix interoperability https://en.wikipedia.org/wiki/Filename
        return mb_strtolower($tmp, $this->encoding);
    }

    private function getExtension(): string {
        $tmpExt = $this->newExtension ?? $this->extension;

        return empty($tmpExt) ? "" : ".{$tmpExt}";
    }

    private function getDirName(): string {
        return $this->withDirectory && '' !== $this->dirname
            ? $this->dirname.DIRECTORY_SEPARATOR
            : '';
    }

    private function cutFilenameLength(): string {
        // cut filename length to 255 bytes http://serverfault.com/a/9548/44086
        $fullLength = mb_strlen(
            $this->getformatedFilename($this->filename),
            $this->encoding
        );

        if ($fullLength <= 255) {
            return $this->filename;
        }

        $filenameLength =  mb_strlen(
            $this->filename,
            $this->encoding
        );

        $mustCutting = $fullLength - 255;

        return mb_strcut(
            string: $this->filename,
            start: 0,
            length: $filenameLength - $mustCutting,
            encoding: $this->encoding
        );
    }
}
